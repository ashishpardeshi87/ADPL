from datetime import datetime
from typing import Optional, List, Dict, Any

from sqlmodel import SQLModel, Field
from sqlalchemy import Column
from sqlalchemy.dialects.sqlite import JSON as SQLITE_JSON


class Message(SQLModel, table=True):
	id: Optional[int] = Field(default=None, primary_key=True)
	source: str = Field(index=True, description="email|social|messaging|other")
	content: str
	sender_address: Optional[str] = Field(default=None, index=True)
	sender_display: Optional[str] = None
	received_at: datetime = Field(default_factory=datetime.utcnow, index=True)
	ip: Optional[str] = Field(default=None, index=True)
	user_agent: Optional[str] = None
	device_fingerprint: Optional[str] = Field(default=None, index=True)
	metadata_raw: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(SQLITE_JSON))
	classification: str = Field(default="unknown", index=True)
	risk_score: float = Field(default=0.0, index=True)
	keywords_hit: Optional[List[str]] = Field(default=None, sa_column=Column(SQLITE_JSON))
	case_id: Optional[int] = Field(default=None, foreign_key="case.id", index=True)
	created_at: datetime = Field(default_factory=datetime.utcnow, index=True)


class Case(SQLModel, table=True):
	id: Optional[int] = Field(default=None, primary_key=True)
	first_seen: datetime = Field(default_factory=datetime.utcnow)
	last_seen: datetime = Field(default_factory=datetime.utcnow)
	risk_level: float = Field(default=0.0, index=True)
	linked_device_fingerprint: Optional[str] = Field(default=None, index=True)
	notes: Optional[str] = None


class BehaviorProfile(SQLModel, table=True):
	id: Optional[int] = Field(default=None, primary_key=True)
	device_fingerprint: str = Field(index=True)
	avg_message_length: float = Field(default=0.0)
	hour_histogram: Optional[Dict[str, float]] = Field(default=None, sa_column=Column(SQLITE_JSON))
	char_bigram_freq: Optional[Dict[str, float]] = Field(default=None, sa_column=Column(SQLITE_JSON))
	updated_at: datetime = Field(default_factory=datetime.utcnow, index=True)


class AuditLog(SQLModel, table=True):
	id: Optional[int] = Field(default=None, primary_key=True)
	action: str = Field(index=True)
	actor: str = Field(default="system", index=True)
	created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
	details: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(SQLITE_JSON))

