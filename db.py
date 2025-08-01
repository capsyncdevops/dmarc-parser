from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite+aiosqlite:///.db.sqlite3"

engine = create_async_engine(DATABASE_URL, echo=True, future=True)

AsyncSessionLocal = sessionmaker(
    engine,  # type: ignore
    expire_on_commit=False,
    class_=AsyncSession,
    autoflush=False,
)  # type: ignore

Base = declarative_base()


async def get_db():
    async with AsyncSessionLocal() as session:  # type: ignore
        yield session
