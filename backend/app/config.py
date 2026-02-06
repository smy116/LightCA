import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # Security
    MASTER_KEY: str = Field(..., min_length=32, description="Master key for encryption (min 32 chars)")
    ADMIN: str = "admin"
    ADMIN_PASSWORD: str = Field(..., description="Admin password (plaintext or bcrypt hash)")

    # Database
    DB_TYPE: str = "sqlite"
    DATABASE_URL: Optional[str] = None

    # JWT
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    JWT_ALGORITHM: str = "HS256"

    # CRL
    CRL_DISTRIBUTION_URL: Optional[str] = None
    CRL_VALIDITY_DAYS: int = 7

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    LOG_LEVEL: str = "info"

    @property
    def get_database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        if self.DB_TYPE == "sqlite":
            db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "lightca.db")
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            return f"sqlite:///{db_path}"
        raise ValueError("DATABASE_URL must be set for non-SQLite databases")


settings = Settings()
