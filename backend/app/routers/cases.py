from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from ..database import engine
from ..models import Case, Message


router = APIRouter()


def get_session():
	with Session(engine) as session:
		yield session


@router.get("/")
def list_cases(session: Session = Depends(get_session)) -> List[Case]:
	statement = select(Case).order_by(Case.last_seen.desc())
	return session.exec(statement).all()


@router.get("/{case_id}")
def get_case(case_id: int, session: Session = Depends(get_session)) -> Case:
	case = session.get(Case, case_id)
	if not case:
		raise HTTPException(status_code=404, detail="Case not found")
	return case


@router.get("/{case_id}/messages")
def get_case_messages(case_id: int, session: Session = Depends(get_session)) -> List[Message]:
	statement = select(Message).where(Message.case_id == case_id).order_by(Message.received_at.desc())
	return session.exec(statement).all()

