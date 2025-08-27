import hashlib
import json
from typing import Any, Dict, Optional


def stable_hash(value: str) -> str:
	return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_device_fingerprint(ip: Optional[str], user_agent: Optional[str], metadata: Dict[str, Any]) -> str:
	parts = {
		"ip": ip or "",
		"ua": user_agent or "",
		"lang": metadata.get("language", ""),
		"tz": metadata.get("timezone", ""),
		"platform": metadata.get("platform", ""),
		"screen": metadata.get("screen", ""),
	}
	raw = json.dumps(parts, sort_keys=True, separators=(",", ":"))
	return stable_hash(raw)

