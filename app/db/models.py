"""
app/db/models.py
SQLAlchemy ORM models for User, Scan, Finding.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.session import Base


def _now():
    return datetime.now(timezone.utc)


def _uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id:           Mapped[str]  = mapped_column(String(36), primary_key=True, default=_uuid)
    username:     Mapped[str]  = mapped_column(String(64), unique=True, nullable=False)
    email:        Mapped[str]  = mapped_column(String(256), unique=True, nullable=False)
    full_name:    Mapped[str]  = mapped_column(String(128), nullable=False)
    hashed_pw:    Mapped[str]  = mapped_column(String(256), nullable=False)
    role:         Mapped[str]  = mapped_column(String(16), default="USER")
    is_active:    Mapped[bool] = mapped_column(Boolean, default=True)
    created_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="owner")


class Scan(Base):
    __tablename__ = "scans"

    id:             Mapped[str]   = mapped_column(String(36), primary_key=True, default=_uuid)
    name:           Mapped[str]   = mapped_column(String(128), nullable=False)
    provider:       Mapped[str]   = mapped_column(String(16), nullable=False)   # aws|azure|gcp
    regions:        Mapped[list]  = mapped_column(JSON, default=list)
    module_ids:     Mapped[list]  = mapped_column(JSON, default=list)
    status:         Mapped[str]   = mapped_column(String(16), default="queued") # queued|running|completed|error
    progress:       Mapped[float] = mapped_column(Float, default=0.0)
    current_module: Mapped[str]   = mapped_column(String(64), default="")
    error_message:  Mapped[str]   = mapped_column(Text, default="")
    created_at:     Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at:     Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at:   Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner_id:       Mapped[str]   = mapped_column(ForeignKey("users.id"), nullable=False)

    owner:    Mapped["User"]          = relationship("User", back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan",
                                                      cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id:               Mapped[str]  = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id:          Mapped[str]  = mapped_column(ForeignKey("scans.id"), nullable=False)
    module_id:        Mapped[str]  = mapped_column(String(64))
    title:            Mapped[str]  = mapped_column(String(256))
    severity:         Mapped[str]  = mapped_column(String(16))   # CRITICAL|HIGH|MEDIUM|LOW|INFO
    description:      Mapped[str]  = mapped_column(Text)
    affected_resource:Mapped[str]  = mapped_column(Text)
    remediation:      Mapped[str]  = mapped_column(Text)
    evidence:         Mapped[dict] = mapped_column(JSON, default=dict)
    cis_controls:     Mapped[list] = mapped_column(JSON, default=list)
    references:       Mapped[list] = mapped_column(JSON, default=list)
    cloud_provider:   Mapped[str]  = mapped_column(String(16))
    region:           Mapped[str]  = mapped_column(String(32), default="")
    status:           Mapped[str]  = mapped_column(String(16), default="open")  # open|accepted|fixed
    discovered_at:    Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
