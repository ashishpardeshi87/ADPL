from typing import Any, Dict, Optional
import ipaddress


def normalize_ip(ip: Optional[str]) -> Optional[str]:
	if not ip:
		return None
	try:
		return str(ipaddress.ip_address(ip.strip()))
	except Exception:
		return None


def extract_ip_from_metadata(metadata: Dict[str, Any]) -> Optional[str]:
	ip = metadata.get("ip") or metadata.get("ip_address") or metadata.get("sender_ip")
	if ip:
		return normalize_ip(ip)
	# Parse x-forwarded-for like headers
	xff = metadata.get("x_forwarded_for")
	if isinstance(xff, str) and "," in xff:
		first = xff.split(",")[0].strip()
		return normalize_ip(first)
	return normalize_ip(xff if isinstance(xff, str) else None)

