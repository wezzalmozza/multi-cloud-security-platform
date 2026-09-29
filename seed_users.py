#!/usr/bin/env python
"""Seed database with demo users"""
import asyncio
from app.db.session import AsyncSessionLocal, engine, Base
from app.db.models import User
from app.core.security import hash_password
from sqlalchemy import select

async def seed_users():
    """Create tables and seed with demo users"""
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # Check if myuser exists
        result = await db.execute(select(User).where(User.username == "myuser"))
        existing = result.scalar_one_or_none()

        if not existing:
            user = User(
                username="myuser",
                email="myuser@example.com",
                full_name="My User",
                hashed_pw=hash_password("mypassword"),
                role="USER"
            )
            db.add(user)
            await db.commit()
            print("✓ Created myuser")
        else:
            print("✓ myuser already exists")

        # Check if admin exists
        result = await db.execute(select(User).where(User.username == "admin"))
        existing = result.scalar_one_or_none()

        if not existing:
            user = User(
                username="admin",
                email="admin@example.com",
                full_name="Admin User",
                hashed_pw=hash_password("password"),
                role="ADMIN"
            )
            db.add(user)
            await db.commit()
            print("✓ Created admin user")
        else:
            print("✓ admin already exists")

if __name__ == "__main__":
    asyncio.run(seed_users())
