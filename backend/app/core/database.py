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

async def get_db():
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


