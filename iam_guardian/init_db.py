import asyncio

import iam_guardian.db_models  # noqa: F401
from iam_guardian.database import Base, engine


async def init() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Tables created.")


asyncio.run(init())
