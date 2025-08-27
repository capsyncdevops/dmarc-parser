import os
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DB_URL", "sqlite+aiosqlite:///./data/dmarc_parser.sqlite3")

engine = create_async_engine(DATABASE_URL, echo=True, future=True)

AsyncSessionLocal = async_sessionmaker(
    engine,  # type: ignore
    expire_on_commit=False,
    class_=AsyncSession,
    autoflush=False,
)  # type: ignore

Base = declarative_base()


async def get_db():
    async with AsyncSessionLocal() as session:  # type: ignore
        yield session
