import os
from typing import Callable
from fastapi import Request, HTTPException


API_KEY = os.getenv("API_KEY", "dev-key-change")


async def api_key_auth_middleware(request: Request, call_next: Callable):
	# Allow unauthenticated access to health and docs
	open_paths = {"/health", "/docs", "/openapi.json"}
	if request.url.path in open_paths or request.url.path.startswith("/docs"):
		return await call_next(request)
	key = request.headers.get("x-api-key")
	if key != API_KEY:
		raise HTTPException(status_code=401, detail="Unauthorized")
	response = await call_next(request)
	return response

