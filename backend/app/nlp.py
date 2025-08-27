from typing import List, Tuple, Dict
import re


DEFAULT_THREAT_KEYWORDS: List[str] = [
	"bomb",
	"explode",
	"detonate",
	"blast",
	"device",
	"timer",
	"threat",
	"kill",
	"massacre",
	"hostage",
	"terror",
	"terrorist",
	"IED",
	"C4",
	"TNT",
]


def build_keyword_regex(keywords: List[str]) -> re.Pattern:
	escaped = [re.escape(k) for k in keywords if k]
	pattern = r"\b(" + "|".join(escaped) + r")\b"
	return re.compile(pattern, flags=re.IGNORECASE)


KEYWORD_REGEX = build_keyword_regex(DEFAULT_THREAT_KEYWORDS)


def extract_keyword_hits(text: str) -> List[str]:
	return sorted({m.group(0).lower() for m in KEYWORD_REGEX.finditer(text or "")})


def heuristic_signals(text: str) -> Dict[str, float]:
	signals: Dict[str, float] = {}
	text_lower = (text or "").lower()
	# Strong phrases
	strong_patterns = [
		"bomb in",
		"bomb at",
		"will detonate",
		"set to explode",
		"threat to",
		"evacuate",
	]
	signals["strong_phrase"] = float(any(p in text_lower for p in strong_patterns))
	# Imperatives and time pressure
	urgency_patterns = ["now", "immediately", "in minutes", "deadline", "countdown"]
	signals["urgency"] = float(any(p in text_lower for p in urgency_patterns))
	# Numbers (counts/times)
	numbers = re.findall(r"\b\d{1,3}\b", text_lower)
	signals["numbers_present"] = 1.0 if len(numbers) >= 1 else 0.0
	return signals


def score_text(text: str) -> Tuple[float, List[str]]:
	keywords = extract_keyword_hits(text)
	signals = heuristic_signals(text)
	score = 0.0
	# keyword score
	score += 2.0 * len(keywords)
	# strong signals
	score += 3.0 * signals.get("strong_phrase", 0.0)
	score += 1.0 * signals.get("urgency", 0.0)
	score += 0.5 * signals.get("numbers_present", 0.0)
	return score, keywords


def classify_text(text: str) -> Tuple[str, float, List[str]]:
	score, keywords = score_text(text)
	classification = "threat" if score >= 3.0 and len(keywords) >= 1 else "benign"
	return classification, score, keywords

