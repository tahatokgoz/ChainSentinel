from datetime import datetime

from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship, backref

from backend.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scenario = Column(String, nullable=False)  # iot, portal, api
    target_host = Column(String, nullable=False)
    target_port = Column(Integer, nullable=False)
    status = Column(String, nullable=False, default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # critical, high, medium, low, info
    category = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    file_path = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="reports")


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    provider = Column(String, nullable=False)
    model = Column(String, nullable=True)
    risk_summary = Column(Text, nullable=True)
    executive_summary = Column(Text, nullable=True)
    attack_chains = Column(Text, nullable=True)
    prioritization = Column(Text, nullable=True)
    mitre_mapping = Column(Text, nullable=True)
    raw_response = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", backref=backref("ai_analyses", cascade="all, delete-orphan"))
