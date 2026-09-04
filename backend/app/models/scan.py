from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(512), nullable=False, unique=True)
    domain = Column(String(256), nullable=False, index=True)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="target_rel", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    target_url = Column(String(512), nullable=False)
    profile = Column(String(32), default="passive") # "passive" or "active"
    status = Column(String(32), default="PENDING")   # PENDING, CRAWLING, FUZZING, ANALYZING, COMPLETED, FAILED
    progress = Column(Integer, default=0)            # 0 to 100
    
    # Severity Metrics
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Domain & SSL Relationship Intelligence (JSON text)
    domain_intel = Column(Text, nullable=True)

    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    target_rel = relationship("Target", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_rel", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    
    title = Column(String(256), nullable=False)
    severity = Column(String(32), nullable=False)    # Critical, High, Medium, Low, Info
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(128), nullable=True)
    owasp_category = Column(String(128), nullable=True)
    cwe = Column(String(64), nullable=True)
    
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    target_url = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_rel = relationship("Scan", back_populates="vulnerabilities")
