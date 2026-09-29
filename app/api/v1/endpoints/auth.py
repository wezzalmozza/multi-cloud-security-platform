"""app/api/v1/endpoints/auth.py"""
from fastapi import APIRouter, HTTPException, status, Depends
from app.schemas.auth import LoginRequest, Token
from app.core.security import verify_password, create_access_token, hash_password
from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.db.models import User
from sqlalchemy import select

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
async def login(req: LoginRequest):
    # Try to find user in database
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User).where(User.username == req.username)
        )
        user = result.scalar_one_or_none()

        if not user or not verify_password(req.password, user.hashed_pw):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        token = create_access_token(user.id, user.role)
        return Token(
            access_token=token,
            expires_in=settings.JWT_EXPIRE_MIN * 60,
            username=user.username,
            role=user.role
        )


@router.post("/create-user")
async def create_user(req: LoginRequest):
    """Create a new user"""
    async with AsyncSessionLocal() as db:
        # Check if user already exists
        result = await db.execute(
            select(User).where(User.username == req.username)
        )
        existing = result.scalar_one_or_none()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already exists"
            )

        # Create new user
        new_user = User(
            username=req.username,
            email=f"{req.username}@example.com",
            full_name=req.username.capitalize(),
            hashed_pw=hash_password(req.password),
            role="USER"
        )
        db.add(new_user)
        await db.commit()

        return {"message": f"User {req.username} created successfully"}
