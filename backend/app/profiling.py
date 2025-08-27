from collections import Counter
from datetime import datetime
from typing import Dict, Optional

from sqlmodel import Session, select

from .models import Message, BehaviorProfile, Case


def _compute_hour_histogram(session: Session, device_fingerprint: str) -> Dict[str, float]:
	messages = session.exec(
		select(Message).where(Message.device_fingerprint == device_fingerprint)
	).all()
	counter = Counter()
	for m in messages:
		hour = m.received_at.hour
		counter[str(hour)] += 1
		total = max(1, sum(counter.values()))
	return {h: c / total for h, c in counter.items()}


def _compute_char_bigrams(text: str) -> Dict[str, float]:
	text = (text or "").lower()
	bigrams = [text[i : i + 2] for i in range(len(text) - 1)]
	counts = Counter(bigrams)
	total = max(1, sum(counts.values()))
	return {k: v / total for k, v in counts.items()}


def update_behavior_profile(session: Session, message: Message) -> BehaviorProfile:
	profile = session.exec(
		select(BehaviorProfile).where(BehaviorProfile.device_fingerprint == message.device_fingerprint)
	).first()
	if not profile:
		profile = BehaviorProfile(device_fingerprint=message.device_fingerprint)
		session.add(profile)
		session.commit()
		session.refresh(profile)

	# Update aggregates
	messages = session.exec(
		select(Message).where(Message.device_fingerprint == message.device_fingerprint)
	).all()
	avg_len = sum(len(m.content) for m in messages) / max(1, len(messages))
	hour_hist = _compute_hour_histogram(session, message.device_fingerprint)
	char_bigram_freq = _compute_char_bigrams(" ".join(m.content for m in messages[-20:]))

	profile.avg_message_length = avg_len
	profile.hour_histogram = hour_hist
	profile.char_bigram_freq = char_bigram_freq
	profile.updated_at = datetime.utcnow()
	session.add(profile)
	session.commit()
	session.refresh(profile)
	return profile


def link_message_to_case(session: Session, message: Message) -> Optional[Case]:
	# Rule-based linking: by device fingerprint first
	case = session.exec(
		select(Case).where(Case.linked_device_fingerprint == message.device_fingerprint)
	).first()
	if not case and message.risk_score >= 3.0:
		# Create a new case for high-risk messages
		case = Case(
			first_seen=message.received_at,
			last_seen=message.received_at,
			risk_level=message.risk_score,
			linked_device_fingerprint=message.device_fingerprint,
		)
		session.add(case)
		session.commit()
		session.refresh(case)

	if case:
		message.case_id = case.id
		case.last_seen = max(case.last_seen, message.received_at)
		case.risk_level = max(case.risk_level, message.risk_score)
		session.add(message)
		session.add(case)
		session.commit()
		session.refresh(case)

	return case

