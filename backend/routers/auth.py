"""
Authentication Router
"""
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime, timezone
import uuid

from .dependencies import (
    UserCreate, UserLogin, UserResponse, TokenResponse, RoleUpdate,
    hash_password, verify_password, create_token, get_current_user,
    get_db, check_permission, ROLES
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    db = get_db()
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id,
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "name": user_data.name,
        "role": "analyst",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user_doc)
    
    token = create_token(user_id, user_data.email)
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user_id,
            email=user_data.email,
            name=user_data.name,
            role="analyst",
            created_at=user_doc["created_at"]
        )
    )

@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    db = get_db()
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user["id"], user["email"])
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            name=user["name"],
            role=user.get("role", "analyst"),
            created_at=user["created_at"]
        )
    )

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)

# User management endpoints (admin)
users_router = APIRouter(prefix="/users", tags=["Users"])

@users_router.patch("/{user_id}/role")
async def update_user_role(user_id: str, role_update: RoleUpdate, current_user: dict = Depends(check_permission("manage_users"))):
    """Update user role (admin only)"""
    db = get_db()
    if role_update.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Valid roles: {list(ROLES.keys())}")
    
    result = await db.users.update_one(
        {"id": user_id},
        {"$set": {"role": role_update.role}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Role updated", "role": role_update.role}

@users_router.get("")
async def list_users(current_user: dict = Depends(check_permission("manage_users"))):
    """List all users (admin only)"""
    db = get_db()
    users = await db.users.find({}, {"_id": 0, "password": 0}).to_list(100)
    return users
