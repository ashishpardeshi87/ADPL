from typing import Any, Dict, Optional
from datetime import datetime
import hashlib

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlmodel import Session

from ..database import engine
from ..models import Message, Case
from ..nlp import classify_text
from ..utils import extract_ip_from_metadata
from ..fingerprint import generate_device_fingerprint
from ..profiling import update_behavior_profile, link_message_to_case


router = APIRouter()


def get_session():
	with Session(engine) as session:
		yield session


@router.post("/message")
def ingest_message(payload: Dict[str, Any], request: Request, session: Session = Depends(get_session)) -> Dict[str, Any]:
	content: str = payload.get("content", "")
	source: str = payload.get("source", "other")
	sender_address: Optional[str] = payload.get("sender_address")
	sender_display: Optional[str] = payload.get("sender_display")
	metadata_raw: Dict[str, Any] = payload.get("metadata", {}) or {}
	received_at_str: Optional[str] = payload.get("received_at")
	received_at = datetime.fromisoformat(received_at_str) if received_at_str else datetime.utcnow()

	client_ip = extract_ip_from_metadata(metadata_raw) or request.headers.get("x-forwarded-for") or request.client.host
	user_agent = metadata_raw.get("user_agent") or request.headers.get("user-agent")
	device_fp = generate_device_fingerprint(client_ip, user_agent, metadata_raw)

	classification, risk_score, keywords = classify_text(content)

	msg = Message(
		source=source,
		content=content,
		sender_address=sender_address,
		sender_display=sender_display,
		received_at=received_at,
		ip=client_ip,
		user_agent=user_agent,
		device_fingerprint=device_fp,
		metadata_raw=metadata_raw,
		classification=classification,
		risk_score=risk_score,
		keywords_hit=keywords or None,
	)
	session.add(msg)
	session.commit()
	session.refresh(msg)

	update_behavior_profile(session, msg)
	case = link_message_to_case(session, msg)

	return {
		"id": msg.id,
		"classification": msg.classification,
		"risk_score": msg.risk_score,
		"keywords": msg.keywords_hit,
		"case_id": case.id if case else None,
	}

