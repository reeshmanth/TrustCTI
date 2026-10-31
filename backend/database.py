import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Load environment configuration from .env file
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. TrustCTI requires PostgreSQL. "
        "Please configure DATABASE_URL in .env, e.g.: "
        "DATABASE_URL=postgresql+psycopg://USERNAME:PASSWORD@HOST:5432/DATABASE_NAME"
    )

if DATABASE_URL.startswith("sqlite"):
    raise RuntimeError(
        "SQLite fallback is disabled. TrustCTI operates exclusively on PostgreSQL. "
        "Please update DATABASE_URL in .env to a valid PostgreSQL connection string."
    )

# Normalize postgresql:// to postgresql+psycopg:// if specified without driver prefix
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

# PostgreSQL engine with connection pooling and health checks
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
