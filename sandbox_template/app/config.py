import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./sandbox.db")
    secret_key: str = os.getenv("SECRET_KEY", "dev-secret-change-in-prod")
    algorithm: str = "HS256"
    session_cookie_name: str = os.getenv("SESSION_COOKIE_NAME", "session")
    session_max_age: int = int(os.getenv("SESSION_MAX_AGE", "86400"))
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))


settings = Settings()
