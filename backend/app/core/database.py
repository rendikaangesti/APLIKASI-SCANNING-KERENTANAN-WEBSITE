from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from app.core.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()

import os

# Ensure SQLite directory exists if using file path
if "sqlite" in settings.DATABASE_URL:
    try:
        raw_path = settings.DATABASE_URL.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", "")
        if raw_path.startswith("./"):
            raw_path = raw_path[2:]
        db_dir = os.path.dirname(raw_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    except Exception as e:
        print(f"[DB DIR INIT WARNING] {e}")

_db_initialized = False

async def get_db():
    global _db_initialized
    if not _db_initialized:
        try:
            await init_db()
            _db_initialized = True
        except Exception as e:
            print(f"[DB INIT ERROR in get_db] {e}")
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
        # Auto-migrate missing columns for SQLite
        if "sqlite" in settings.DATABASE_URL:
            def sync_sqlite_columns(connection):
                try:
                    result = connection.exec_driver_sql("PRAGMA table_info(scans)")
                    columns = [row[1] for row in result.fetchall()]
                    if columns and "domain_intel" not in columns:
                        connection.exec_driver_sql("ALTER TABLE scans ADD COLUMN domain_intel TEXT")
                except Exception as e:
                    print(f"[DB INIT ERROR] Migration exception: {e}")
            
            await conn.run_sync(sync_sqlite_columns)


