"""Settings, read from environment variables.

Docker Compose loads .env and passes the values in, so nothing is hard-coded
here. A required value that is missing stops the app at startup (fail fast).
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    field_encryption_key: str
    backup_key: str

    # The ONLY browser origin allowed to call the API directly (development).
    frontend_origin: str = "http://localhost:5173"


settings = Settings()
