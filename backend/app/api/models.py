from fastapi import APIRouter, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text, or_, and_
from typing import Optional, List
import jwt
import logging
from datetime import datetime
from app.db.session import engine
import os

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

logger = logging.getLogger("uvicorn.error")

router = APIRouter()

# Pydantic模型定义
class ModelResponse(BaseModel):
    id: int
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    model_path: Optional[str] = None
    file_size: Optional[int] = None
    model_type: str
    is_public: int
    created_by: Optional[str] = None
    status: str
    created_at: str
    model_category: Optional[str] = None
    # 前端需要的字段
    type: Optional[str] = None  # 映射到model_category显示
    source: str  # 映射到model_type
    createTime: str  # 映射到created_at
    isEditable: bool

class ModelUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


def get_current_user_id(request: Request, authorization: Optional[str] = None) -> Optional[int]:
    """从Authorization header、query params或cookies中提取用户ID"""
    token = None
    if authorization:
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1]
        else:
            token = authorization
    if not token:
        token = request.query_params.get("token") or request.cookies.get("token")
    if not token:
        return None
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        return int(user_id) if user_id else None
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except Exception as e:
        logger.error(f"Token decode error: {e}")
        return None


def map_model_category_to_type(category: Optional[str]) -> Optional[str]:
    """将数据库的model_category映射到前端显示的type"""
    if category == "malicious":
        return "恶意性检测"
    elif category == "impersonation":
        return "仿冒域名检测"
    return None


def format_datetime(dt: Optional[datetime]) -> str:
    """格式化datetime为前端需要的格式"""
    if not dt:
        return ""
    if isinstance(dt, str):
        return dt
    return dt.strftime("%Y-%m-%d %H:%M")


@router.get("/api/models/available")
async def get_available_models(
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    获取当前用户可用的模型列表（用于任务创建时的模型选择）
    返回简化的模型信息：id和name
    逻辑与my-models一致，从user_models表查询
    """
    user_id = get_current_user_id(request, authorization)
    username = None
    
    # 如果有有效的用户ID，获取用户名
    if user_id:
        with engine.connect() as conn:
            user_query = text("SELECT username FROM users WHERE id = :user_id LIMIT 1")
            user_row = conn.execute(user_query, {"user_id": user_id}).mappings().first()
            if user_row:
                username = user_row["username"]
    
    if user_id and username:
        # 已认证用户：从user_models表查询
        query = text("""
            SELECT 
                m.id, m.name
            FROM user_models um
            INNER JOIN models m ON um.model_id = m.id
            WHERE um.user_id = :user_id
              AND m.status = 'active'
              AND um.is_active = 1
            ORDER BY 
                CASE um.source 
                    WHEN 'official' THEN 1 
                    WHEN 'custom' THEN 2 
                    WHEN 'market' THEN 3 
                END,
                um.acquired_at DESC
        """)
        params = {"user_id": user_id}
    else:
        # 未认证或token过期：只返回官方模型
        query = text("""
            SELECT 
                m.id, m.name
            FROM models m
            WHERE m.status = 'active' AND m.model_type = 'official'
            ORDER BY m.created_at DESC
        """)
        params = {}
    
    with engine.connect() as conn:
        rows = conn.execute(query, params).mappings().all()
    
    models = []
    for row in rows:
        models.append({
            "id": row["id"],
            "name": row["name"],
        })
    
    return {"code": 0, "message": "ok", "data": models}


@router.get("/api/models/my-models")
async def get_my_models(
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    获取当前用户的模型列表
    统一从user_models表查询，然后关联models表获取模型信息
    source字段从user_models表获取
    """
    user_id = get_current_user_id(request, authorization)
    username = None
    
    # 如果有有效的用户ID，获取用户名
    if user_id:
        with engine.connect() as conn:
            user_query = text("SELECT username FROM users WHERE id = :user_id LIMIT 1")
            user_row = conn.execute(user_query, {"user_id": user_id}).mappings().first()
            if user_row:
                username = user_row["username"]
    
    if user_id and username:
        # 已认证用户：统一从user_models表查询，关联models表获取模型信息
        # JOIN users表获取创建者的用户名，用于判断isEditable
        # 处理created_by可能是用户ID（数字）或用户名（字符串）的情况
        query = text("""
            SELECT 
                m.id, m.name, m.version, m.description, m.model_path, m.file_size,
                m.model_type, m.is_public,
                m.created_by, m.status, m.created_at, m.model_category,
                um.source, um.acquired_at, um.is_active as user_model_active,
                u.username as creator_username
            FROM user_models um
            INNER JOIN models m ON um.model_id = m.id
            LEFT JOIN users u ON (
                CASE 
                    WHEN m.created_by REGEXP '^[0-9]+$' THEN CAST(m.created_by AS UNSIGNED) = u.id
                    ELSE m.created_by = u.username
                END
            )
            WHERE um.user_id = :user_id
              AND m.status = 'active'
              AND um.is_active = 1
            ORDER BY 
                CASE um.source 
                    WHEN 'official' THEN 1 
                    WHEN 'custom' THEN 2 
                    WHEN 'market' THEN 3 
                END,
                um.acquired_at DESC
        """)
        params = {"user_id": user_id}
    else:
        # 未认证或token过期：只返回官方模型（从models表查询，设置source='official'）
        query = text("""
            SELECT 
                m.id, m.name, m.version, m.description, m.model_path, m.file_size,
                m.model_type, m.is_public,
                m.created_by, m.status, m.created_at, m.model_category,
                'official' as source, NULL as acquired_at, NULL as user_model_active,
                NULL as creator_username
            FROM models m
            WHERE m.status = 'active' AND m.model_type = 'official'
            ORDER BY m.created_at DESC
        """)
        params = {}
    
    with engine.connect() as conn:
        rows = conn.execute(query, params).mappings().all()
    
    models = []
    for row in rows:
        model_type = row["model_type"] or "custom"
        created_by = row["created_by"]  # 可能是用户ID或用户名
        creator_username = row.get("creator_username")  # 从users表获取的用户名
        source = row.get("source") or "custom"  # 从user_models.source获取
        
        # 判断是否可编辑：
        # 1. source='custom'（自定义模型）
        # 2. creator_username存在且等于当前用户名（模型创建者是当前用户）
        # 或者created_by是字符串且等于当前用户名（兼容created_by直接存储用户名的情况）
        is_editable = False
        if source == "custom" and username:
            if creator_username and creator_username == username:
                is_editable = True
            elif isinstance(created_by, str) and created_by == username:
                is_editable = True
            elif isinstance(created_by, (int, str)) and str(created_by).isdigit():
                # 如果created_by是数字（用户ID），检查是否等于当前用户ID
                try:
                    created_by_id = int(created_by)
                    if created_by_id == user_id:
                        is_editable = True
                except (ValueError, TypeError):
                    pass
        
        model_data = {
            "id": row["id"],
            "name": row["name"],
            "version": row["version"],
            "description": row["description"] or "",
            "model_path": row["model_path"],
            "file_size": row["file_size"],
            "model_type": model_type,
            "is_public": row["is_public"],
            "created_by": created_by,  # 保留原始值（可能是ID或用户名）
            "status": row["status"],
            "created_at": format_datetime(row["created_at"]),
            "model_category": row["model_category"],
            "type": map_model_category_to_type(row["model_category"]),
            "source": source,  # 直接使用user_models.source
            "createTime": format_datetime(row["created_at"]),
            "isEditable": is_editable,
        }
        models.append(model_data)
    
    return {"code": 0, "message": "ok", "data": models}


@router.put("/api/models/{model_id}")
async def update_model(
    model_id: int,
    payload: ModelUpdateRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """更新模型信息（仅限用户自定义模型）"""
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 获取用户信息
    with engine.connect() as conn:
        user_query = text("SELECT username FROM users WHERE id = :user_id LIMIT 1")
        user_row = conn.execute(user_query, {"user_id": user_id}).mappings().first()
        if not user_row:
            raise HTTPException(status_code=404, detail="用户不存在")
        username = user_row["username"]
    
    # 检查模型是否存在且属于当前用户（通过user_models表检查source='custom'）
    with engine.connect() as conn:
        # 检查user_models表中是否存在该用户的模型关联，且source='custom'
        user_model_query = text("""
            SELECT um.source, m.id, m.name, m.created_by, m.model_type 
            FROM user_models um
            INNER JOIN models m ON um.model_id = m.id
            WHERE um.user_id = :user_id 
              AND um.model_id = :model_id 
              AND m.status = 'active'
        """)
        user_model_row = conn.execute(user_model_query, {"user_id": user_id, "model_id": model_id}).mappings().first()
        
        if not user_model_row:
            raise HTTPException(status_code=404, detail="模型不存在或不属于当前用户")
        
        # 只有source='custom'且created_by=当前用户的模型才能编辑
        if user_model_row["source"] != "custom" or user_model_row["created_by"] != username:
            raise HTTPException(status_code=403, detail="只能编辑自己创建的自定义模型")
    
    # 更新模型
    updates = []
    params = {"model_id": model_id}
    
    if payload.name is not None:
        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="模型名称不能为空")
        updates.append("name = :name")
        params["name"] = name
    
    if payload.description is not None:
        updates.append("description = :description")
        params["description"] = payload.description.strip()
    
    if not updates:
        raise HTTPException(status_code=400, detail="没有要更新的字段")
    
    # models表中没有updated_at字段，已移除
    
    update_query = text(f"""
        UPDATE models 
        SET {', '.join(updates)}
        WHERE id = :model_id
    """)
    
    try:
        with engine.begin() as conn:
            conn.execute(update_query, params)
        return {"code": 0, "message": "更新成功"}
    except Exception as e:
        logger.exception("更新模型失败")
        raise HTTPException(status_code=500, detail="更新失败")


@router.delete("/api/models/{model_id}")
async def delete_model(
    model_id: int,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """删除模型（仅限用户自定义模型）"""
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 获取用户信息
    with engine.connect() as conn:
        user_query = text("SELECT username FROM users WHERE id = :user_id LIMIT 1")
        user_row = conn.execute(user_query, {"user_id": user_id}).mappings().first()
        if not user_row:
            raise HTTPException(status_code=404, detail="用户不存在")
        username = user_row["username"]
    
    # 检查模型是否存在且属于当前用户（通过user_models表检查source='custom'）
    with engine.connect() as conn:
        # 检查user_models表中是否存在该用户的模型关联，且source='custom'
        user_model_query = text("""
            SELECT um.source, m.id, m.created_by, m.model_type 
            FROM user_models um
            INNER JOIN models m ON um.model_id = m.id
            WHERE um.user_id = :user_id 
              AND um.model_id = :model_id
        """)
        user_model_row = conn.execute(user_model_query, {"user_id": user_id, "model_id": model_id}).mappings().first()
        
        if not user_model_row:
            raise HTTPException(status_code=404, detail="模型不存在或不属于当前用户")
        
        # 只有source='custom'且created_by=当前用户的模型才能删除
        if user_model_row["source"] != "custom" or user_model_row["created_by"] != username:
            raise HTTPException(status_code=403, detail="只能删除自己创建的自定义模型")
    
    # 删除操作：
    # 1. 如果source='custom'，软删除models表（将status设置为inactive）
    # 2. 同时删除user_models表中的关联记录
    try:
        with engine.begin() as conn:
            # 软删除models表
            # 注意：models表中没有updated_at字段
            delete_model_query = text("""
                UPDATE models 
                SET status = 'inactive'
                WHERE id = :model_id
            """)
            conn.execute(delete_model_query, {"model_id": model_id})
            
            # 删除user_models表中的关联记录
            delete_user_model_query = text("""
                DELETE FROM user_models 
                WHERE user_id = :user_id AND model_id = :model_id
            """)
            conn.execute(delete_user_model_query, {"user_id": user_id, "model_id": model_id})
        
        return {"code": 0, "message": "删除成功"}
    except Exception as e:
        logger.exception("删除模型失败")
        raise HTTPException(status_code=500, detail="删除失败")


@router.get("/api/models/publishable")
async def get_publishable_models(
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    获取当前用户可以公开到市场的模型列表
    条件：自定义模型 + 未公开 + 属于当前用户
    """
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 获取用户名
    with engine.connect() as conn:
        user_query = text("SELECT username FROM users WHERE id = :user_id LIMIT 1")
        user_row = conn.execute(user_query, {"user_id": user_id}).mappings().first()
        if not user_row:
            raise HTTPException(status_code=404, detail="用户不存在")
        username = user_row["username"]
    
    # 查询可公开的模型：自定义 + 未公开 + 属于当前用户
    query = text("""
        SELECT 
            m.id, m.name, m.version, m.description, m.model_path, m.file_size,
            m.model_type, m.model_category, m.is_public,
            m.created_by, m.status, m.created_at
        FROM user_models um
        INNER JOIN models m ON um.model_id = m.id
        INNER JOIN users u ON u.id = um.user_id
        WHERE um.user_id = :user_id
          AND um.is_active = 1
          AND um.source = 'custom'
          AND m.model_type = 'custom'
          AND m.is_public = 0
          AND m.status = 'active'
          AND m.created_by = u.username
        ORDER BY m.created_at DESC
    """)
    
    with engine.connect() as conn:
        rows = conn.execute(query, {"user_id": user_id}).mappings().all()
    
    models = []
    for row in rows:
        models.append({
            "id": row["id"],
            "name": row["name"],
            "version": row["version"],
            "description": row["description"] or "",
            "model_path": row["model_path"],
            "file_size": row["file_size"],
            "model_type": row["model_type"],
            "model_category": row["model_category"],
            "is_public": row["is_public"],
            "created_by": row["created_by"],
            "status": row["status"],
            "created_at": format_datetime(row["created_at"]),
            "type": map_model_category_to_type(row["model_category"]),
            "createTime": format_datetime(row["created_at"]),
        })
    
    return {"code": 0, "message": "ok", "data": models}


@router.get("/api/models/market")
async def get_market_models(
    request: Request,
    authorization: Optional[str] = Header(None),
    category: Optional[str] = None,
    keyword: Optional[str] = None
):
    """
    获取模型市场公共列表
    返回所有已公开的模型（is_public=1）
    如果指定category，只返回该类型的模型（malicious/impersonation）
    """
    user_id = get_current_user_id(request, authorization)
    
    # 构建查询条件
    conditions = ["m.status = 'active'", "m.is_public = 1"]
    params = {}
    
    # 如果指定了category，只返回该类型的模型
    # 如果不指定category，返回所有类型的公开模型
    if category and category in ["malicious", "impersonation"]:
        conditions.append("m.model_category = :category")
        params["category"] = category
    # 移除默认限制，允许显示所有类型的公开模型
    
    # 如果有关键词搜索
    if keyword and keyword.strip():
        conditions.append("(m.name LIKE :keyword OR m.description LIKE :keyword OR m.created_by LIKE :keyword)")
        params["keyword"] = f"%{keyword.strip()}%"
    
    where_clause = " AND ".join(conditions)
    
    # 查询模型市场列表，JOIN users表获取用户名
    # 处理created_by可能是用户ID（数字）或用户名（字符串）的情况
    query = text(f"""
        SELECT 
            m.id, m.name, m.version, m.description, m.model_path, m.file_size,
            m.model_type, m.model_category, m.is_public,
            m.created_by, m.status, m.created_at,
            u.username as creator_username,
            CASE WHEN um.id IS NOT NULL THEN 1 ELSE 0 END as is_added
        FROM models m
        LEFT JOIN users u ON (
            CASE 
                WHEN m.created_by REGEXP '^[0-9]+$' THEN CAST(m.created_by AS UNSIGNED) = u.id
                ELSE m.created_by = u.username
            END
        )
        LEFT JOIN user_models um ON m.id = um.model_id 
            AND um.user_id = :user_id 
            AND um.is_active = 1
        WHERE {where_clause}
        ORDER BY m.created_at DESC
    """)
    
    params["user_id"] = user_id if user_id else 0  # 如果未登录，使用0作为占位符
    
    with engine.connect() as conn:
        rows = conn.execute(query, params).mappings().all()
    
    models = []
    for row in rows:
        # 优先使用creator_username，如果不存在则使用created_by（可能是用户名或ID）
        creator_name = row.get("creator_username") or row["created_by"] or "未知"
        models.append({
            "id": row["id"],
            "name": row["name"],
            "version": row["version"],
            "description": row["description"] or "",
            "model_path": row["model_path"],
            "file_size": row["file_size"],
            "model_type": row["model_type"],
            "model_category": row["model_category"],
            "is_public": row["is_public"],
            "created_by": row["created_by"],  # 保留原始值
            "status": row["status"],
            "created_at": format_datetime(row["created_at"]),
            "type": map_model_category_to_type(row["model_category"]),
            "creator": creator_name,  # 使用用户名
            "isAdded": bool(row["is_added"]),
        })
    
    return {"code": 0, "message": "ok", "data": models}


class PublishModelRequest(BaseModel):
    description: Optional[str] = None


@router.post("/api/models/{model_id}/publish")
async def publish_model_to_market(
    model_id: int,
    payload: PublishModelRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    发布模型到市场（将is_public设置为1）
    只有自定义且未公开的模型才能发布
    可以同时更新模型描述
    """
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 获取用户名
    with engine.connect() as conn:
        user_query = text("SELECT username FROM users WHERE id = :user_id LIMIT 1")
        user_row = conn.execute(user_query, {"user_id": user_id}).mappings().first()
        if not user_row:
            raise HTTPException(status_code=404, detail="用户不存在")
        username = user_row["username"]
    
    # 检查模型是否存在且属于当前用户，且可以发布
    with engine.connect() as conn:
        model_query = text("""
            SELECT m.id, m.name, m.model_type, m.is_public, m.created_by, m.status,
                   um.source, um.user_id
            FROM models m
            INNER JOIN user_models um ON m.id = um.model_id
            WHERE m.id = :model_id
              AND um.user_id = :user_id
              AND um.source = 'custom'
              AND m.model_type = 'custom'
              AND m.status = 'active'
        """)
        model_row = conn.execute(model_query, {"model_id": model_id, "user_id": user_id}).mappings().first()
        
        if not model_row:
            raise HTTPException(status_code=404, detail="模型不存在或不属于当前用户")
        
        if model_row["is_public"] == 1:
            raise HTTPException(status_code=400, detail="该模型已经公开到市场")
        
        # 验证权限：
        # 1. 如果source='custom'且user_id匹配，说明是用户自己的模型，允许发布
        # 2. 如果created_by存在，也检查是否匹配（但这不是必要条件，因为source='custom'已经验证了所有权）
        # 如果created_by不匹配，记录警告但不阻止发布
        created_by = model_row.get("created_by")
        if created_by and created_by != username:
            logger.warning(f"模型 {model_id} 的 created_by ({created_by}) 与当前用户 ({username}) 不匹配，但 source='custom' 且 user_id 匹配，允许发布")
        
        # 如果source='custom'且user_id匹配，就允许发布（这是主要验证条件）
        # created_by的匹配只是辅助验证，不作为必要条件
    
    # 构建更新语句
    updates = ["is_public = 1"]
    params = {"model_id": model_id}
    
    # 如果提供了描述，更新描述
    if payload.description is not None:
        updates.append("description = :description")
        params["description"] = payload.description.strip()
    
    update_query = text(f"""
        UPDATE models 
        SET {', '.join(updates)}
        WHERE id = :model_id
    """)
    
    try:
        with engine.begin() as conn:
            conn.execute(update_query, params)
        return {"code": 0, "message": "模型已成功发布到市场"}
    except Exception as e:
        logger.exception("发布模型失败")
        raise HTTPException(status_code=500, detail="发布失败")


@router.post("/api/models/{model_id}/unpublish")
async def unpublish_model_from_market(
    model_id: int,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    取消公开模型（将is_public设置为0）
    只有模型创建者才能取消公开
    """
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 获取用户名
    with engine.connect() as conn:
        user_query = text("SELECT username FROM users WHERE id = :user_id LIMIT 1")
        user_row = conn.execute(user_query, {"user_id": user_id}).mappings().first()
        if not user_row:
            raise HTTPException(status_code=404, detail="用户不存在")
        username = user_row["username"]
    
    # 检查模型是否存在且属于当前用户
    with engine.connect() as conn:
        model_query = text("""
            SELECT m.id, m.name, m.is_public, m.created_by, m.status,
                   um.source, um.user_id
            FROM models m
            LEFT JOIN user_models um ON m.id = um.model_id 
                AND um.user_id = :user_id 
                AND um.is_active = 1
            WHERE m.id = :model_id
              AND m.status = 'active'
        """)
        model_row = conn.execute(model_query, {"model_id": model_id, "user_id": user_id}).mappings().first()
        
        if not model_row:
            raise HTTPException(status_code=404, detail="模型不存在")
        
        if model_row["is_public"] == 0:
            raise HTTPException(status_code=400, detail="该模型尚未公开到市场")
        
        # 验证权限：如果source='custom'且user_id匹配，说明是用户自己的模型，允许取消公开
        # 或者如果created_by匹配，也允许取消公开
        source = model_row.get("source")
        created_by = model_row.get("created_by")
        
        # 如果source='custom'且user_id匹配，说明是用户自己的模型
        if source == "custom" and model_row.get("user_id") == user_id:
            # 允许取消公开
            pass
        elif created_by and created_by == username:
            # 如果created_by匹配，也允许取消公开
            pass
        else:
            raise HTTPException(status_code=403, detail="只能取消公开自己创建的模型")
    
    # 更新模型为私有状态
    update_query = text("""
        UPDATE models 
        SET is_public = 0
        WHERE id = :model_id
    """)
    
    try:
        with engine.begin() as conn:
            conn.execute(update_query, {"model_id": model_id})
        return {"code": 0, "message": "已取消公开"}
    except Exception as e:
        logger.exception("取消公开失败")
        raise HTTPException(status_code=500, detail="取消公开失败")


@router.post("/api/models/{model_id}/acquire")
async def acquire_model_from_market(
    model_id: int,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    从市场获取模型（在user_models表中创建记录，source='market'）
    """
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 检查模型是否存在且已公开
    with engine.connect() as conn:
        model_query = text("""
            SELECT m.id, m.name, m.is_public, m.status, m.model_category
            FROM models m
            WHERE m.id = :model_id
              AND m.status = 'active'
        """)
        model_row = conn.execute(model_query, {"model_id": model_id}).mappings().first()
        
        if not model_row:
            raise HTTPException(status_code=404, detail="模型不存在")
        
        if model_row["is_public"] != 1:
            raise HTTPException(status_code=400, detail="该模型尚未公开到市场")
        
        # 检查用户是否已经获取过该模型
        user_model_query = text("""
            SELECT id FROM user_models 
            WHERE user_id = :user_id AND model_id = :model_id
        """)
        existing = conn.execute(user_model_query, {"user_id": user_id, "model_id": model_id}).first()
        
        if existing:
            raise HTTPException(status_code=400, detail="您已经获取过该模型")
    
    # 在user_models表中创建记录
    insert_query = text("""
        INSERT INTO user_models (user_id, model_id, acquired_at, is_active, source)
        VALUES (:user_id, :model_id, NOW(), 1, 'market')
    """)
    
    try:
        with engine.begin() as conn:
            conn.execute(insert_query, {"user_id": user_id, "model_id": model_id})
        return {"code": 0, "message": "模型已添加到我的模型"}
    except Exception as e:
        logger.exception("获取模型失败")
        raise HTTPException(status_code=500, detail="获取模型失败")


@router.delete("/api/models/{model_id}/acquire")
async def remove_acquired_model(
    model_id: int,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    从我的模型中移除从市场获取的模型（删除user_models表中的记录）
    只能移除source='market'的模型
    """
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 检查user_models记录是否存在且source='market'
    with engine.connect() as conn:
        user_model_query = text("""
            SELECT um.id, um.source
            FROM user_models um
            WHERE um.user_id = :user_id 
              AND um.model_id = :model_id
        """)
        user_model_row = conn.execute(user_model_query, {"user_id": user_id, "model_id": model_id}).mappings().first()
        
        if not user_model_row:
            raise HTTPException(status_code=404, detail="该模型不在您的模型列表中")
        
        if user_model_row["source"] != "market":
            raise HTTPException(status_code=403, detail="只能移除从市场获取的模型")
    
    # 删除user_models记录
    delete_query = text("""
        DELETE FROM user_models 
        WHERE user_id = :user_id AND model_id = :model_id
    """)
    
    try:
        with engine.begin() as conn:
            conn.execute(delete_query, {"user_id": user_id, "model_id": model_id})
        return {"code": 0, "message": "已从我的模型中移除"}
    except Exception as e:
        logger.exception("移除模型失败")
        raise HTTPException(status_code=500, detail="移除失败")
