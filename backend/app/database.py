import os
from sqlmodel import SQLModel, create_engine


DB_PATH = os.getenv("DB_PATH", "/workspace/backend/db.sqlite3")
DATABASE_URL = f"sqlite:///{DB_PATH}"


engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})


def init_db() -> None:
	from . import models  # noqa: F401 - ensure models are imported for table creation
	SQLModel.metadata.create_all(engine)

