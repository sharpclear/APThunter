from fastapi import APIRouter, HTTPException, status, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timedelta
from sqlalchemy import text
from typing import Optional
import os
import jwt
import re
import logging, traceback
# 复用数据库连接
from app.db.session import engine

logger = logging.getLogger("uvicorn.error")

router = APIRouter()

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))


class LoginIn(BaseModel):
    username: str
    password: str


class RegisterIn(BaseModel):
    username: str
    password: str
    email: Optional[str] = None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pbkdf2_sha256.verify(plain_password, hashed_password)
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token


@router.post("/api/login")
async def login(payload: LoginIn):
    query = text("SELECT id, username, password_hash, email FROM users WHERE username = :u LIMIT 1")
    with engine.connect() as conn:
        row = conn.execute(query, {"u": payload.username}).mappings().first()

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token({"sub": str(row["id"]), "username": row["username"]})
    user_info = {"userid": str(row["id"]), "username": row["username"], "email": row.get("email")}

    return {"code": 0, "message": "ok", "data": {"token": access_token, "user": user_info}}


@router.post("/api/register")
async def register(payload: RegisterIn):
    username = (payload.username or "").strip()
    password = payload.password or ""
    email = (payload.email or "").strip() or None

    # 基本校验
    if not username or len(username) < 3 or len(username) > 20 or not re.match(r'^[A-Za-z0-9_]+$', username):
        return JSONResponse(status_code=400, content={"success": False, "message": "用户名规则：3-20字符，仅允许字母数字和下划线"})

    if email and not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
        return JSONResponse(status_code=400, content={"success": False, "message": "请输入有效的邮箱地址"})

    try:
        with engine.begin() as conn:
            # 检查用户名是否存在
            exists = conn.execute(text("SELECT id FROM users WHERE username = :u LIMIT 1"), {"u": username}).mappings().first()
            if exists:
                return JSONResponse(status_code=400, content={"success": False, "message": "用户名已被占用"})

            # 生成密码哈希并插入
            hashed = pbkdf2_sha256.hash(password)
            
            # 执行插入
            result = conn.execute(
                text("INSERT INTO users (username, password_hash, email) VALUES (:username, :password_hash, :email)"),
                {"username": username, "password_hash": hashed, "email": email}
            )
            
            # 获取新插入的用户ID
            new = conn.execute(text("SELECT id FROM users WHERE username = :u LIMIT 1"), {"u": username}).mappings().first()
            user_id = new["id"] if new else None

        return JSONResponse(status_code=200, content={
            "success": True, 
            "message": "注册成功", 
            "data": {"userId": str(user_id)}, 
            "code": 0
        })
        
    except Exception as e:
        logger.exception("注册错误")
        return JSONResponse(
            status_code=500, 
            content={
                "success": False, 
                "message": "注册失败，内部错误",
                "code": 500
            }
        )


@router.get("/api/user/info")
async def user_info(request: Request, authorization: Optional[str] = Header(None)):
    token = None
    if authorization:
        if authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1]
        else:
            token = authorization
    if not token:
        token = request.query_params.get("token") or request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    query = text("SELECT id, username, email FROM users WHERE id = :id LIMIT 1")
    with engine.connect() as conn:
        row = conn.execute(query, {"id": user_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # 从数据库获取用户名
    db_username = row["username"]
    
    # 如果username看起来像JWT token（包含JWT特征），尝试从token payload中提取username
    # 或者使用payload中的username（如果token中包含）
    actual_username = db_username
    if db_username and ("alg" in db_username or "JWT" in db_username or "sub" in db_username):
        # username字段被错误地存储了token，尝试从payload中提取
        try:
            # payload中可能包含username
            token_username = payload.get("username")
            if token_username:
                actual_username = token_username
                logger.warning(f"用户 {user_id} 的username字段存储了token，使用payload中的username: {token_username}")
        except Exception as e:
            logger.error(f"无法从payload提取username: {e}")
    
    return {
        "code": 200,  # 使用200以匹配前端期望的格式
        "msg": "获取成功",
        "data": {
            "id": str(row["id"]),  # 使用id而不是userid，匹配前端接口
            "userid": str(row["id"]),  # 保留userid以兼容旧代码
            "username": actual_username, 
            "nickname": actual_username,  # 使用username作为nickname显示
            "email": row.get("email") or "",
            "avatar": "",  # 默认头像
            "roles": []  # 角色信息
        }
    }