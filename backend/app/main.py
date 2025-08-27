from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import init_db
from .routers import ingest, cases
from .compliance import api_key_auth_middleware


app = FastAPI(title="Threat Intelligence Backend", version="0.1.0")


# CORS - adjust in production
app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)


# API key auth middleware
app.middleware("http")(api_key_auth_middleware)


@app.on_event("startup")
def on_startup() -> None:
	init_db()


app.include_router(ingest.router, prefix="/api/ingest", tags=["ingest"])
app.include_router(cases.router, prefix="/api/cases", tags=["cases"])


@app.get("/health")
def health() -> dict:
	return {"status": "ok"}

