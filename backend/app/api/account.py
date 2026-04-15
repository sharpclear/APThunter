from fastapi import APIRouter, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
from typing import Optional
import jwt
import logging
import os
from passlib.hash import pbkdf2_sha256
from app.db.session import engine

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

logger = logging.getLogger("uvicorn.error")

router = APIRouter()


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


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码"""
    try:
        return pbkdf2_sha256.verify(plain_password, hashed_password)
    except Exception:
        return False


# Pydantic模型定义
class ProfileResponse(BaseModel):
    email: Optional[str] = None
    name: Optional[str] = None
    bio: Optional[str] = None


class ProfileUpdateRequest(BaseModel):
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    bio: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str


@router.get("/api/account/profile")
async def get_profile(
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    获取当前用户的基本信息
    """
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 查询用户信息
    query = text("""
        SELECT email, username, bio
        FROM users
        WHERE id = :user_id
        LIMIT 1
    """)
    
    with engine.connect() as conn:
        row = conn.execute(query, {"user_id": user_id}).mappings().first()
        
        if not row:
            raise HTTPException(status_code=404, detail="用户不存在")
        
        return {
            "code": 0,
            "message": "ok",
            "data": {
                "email": row["email"] or "",
                "name": row["username"] or "",  # 使用username作为name
                "bio": row.get("bio") or "",  # bio字段可能不存在，使用get方法
            }
        }


@router.put("/api/account/profile")
async def update_profile(
    payload: ProfileUpdateRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    更新当前用户的基本信息
    """
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 构建更新语句
    updates = []
    params = {"user_id": user_id}
    
    if payload.email is not None:
        updates.append("email = :email")
        params["email"] = payload.email
    
    if payload.name is not None:
        updates.append("username = :name")
        params["name"] = payload.name
    
    if payload.bio is not None:
        updates.append("bio = :bio")
        params["bio"] = payload.bio
    
    if not updates:
        raise HTTPException(status_code=400, detail="没有要更新的字段")
    
    # 检查用户名是否已被其他用户使用
    if payload.name is not None:
        check_query = text("""
            SELECT id FROM users 
            WHERE username = :name AND id != :user_id
            LIMIT 1
        """)
        with engine.connect() as conn:
            existing = conn.execute(check_query, {"name": payload.name, "user_id": user_id}).first()
            if existing:
                raise HTTPException(status_code=400, detail="该用户名已被使用")
    
    # 检查邮箱是否已被其他用户使用
    if payload.email is not None:
        check_query = text("""
            SELECT id FROM users 
            WHERE email = :email AND id != :user_id AND email IS NOT NULL
            LIMIT 1
        """)
        with engine.connect() as conn:
            existing = conn.execute(check_query, {"email": payload.email, "user_id": user_id}).first()
            if existing:
                raise HTTPException(status_code=400, detail="该邮箱已被使用")
    
    # 执行更新
    update_query = text(f"""
        UPDATE users 
        SET {', '.join(updates)}
        WHERE id = :user_id
    """)
    
    try:
        with engine.begin() as conn:
            conn.execute(update_query, params)
        return {"code": 0, "message": "更新成功"}
    except Exception as e:
        logger.exception("更新用户信息失败")
        raise HTTPException(status_code=500, detail="更新失败")


@router.put("/api/account/password")
async def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    修改当前用户的密码
    """
    user_id = get_current_user_id(request, authorization)
    if not user_id:
        raise HTTPException(status_code=401, detail="未认证或token已过期，请重新登录")
    
    # 验证新密码长度
    if len(payload.new_password) < 4:
        raise HTTPException(status_code=400, detail="新密码长度至少4位")
    
    # 查询当前用户的密码哈希
    query = text("""
        SELECT password_hash
        FROM users
        WHERE id = :user_id
        LIMIT 1
    """)
    
    with engine.connect() as conn:
        row = conn.execute(query, {"user_id": user_id}).mappings().first()
        
        if not row:
            raise HTTPException(status_code=404, detail="用户不存在")
        
        # 验证旧密码
        if not verify_password(payload.old_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="当前密码不正确")
    
    # 生成新密码哈希
    new_password_hash = pbkdf2_sha256.hash(payload.new_password)
    
    # 更新密码
    update_query = text("""
        UPDATE users 
        SET password_hash = :new_password_hash
        WHERE id = :user_id
    """)
    
    try:
        with engine.begin() as conn:
            conn.execute(update_query, {"user_id": user_id, "new_password_hash": new_password_hash})
        return {"code": 0, "message": "密码修改成功"}
    except Exception as e:
        logger.exception("修改密码失败")
        raise HTTPException(status_code=500, detail="修改密码失败")
