from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    OPEN_SEARCH_URL: str = "http://localhost:9200"
    OPEN_SEARCH_INDEX: str = "versionguard-cves"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    API_KEY: str = "changeme"
    UI_ORIGIN: str = "http://localhost:5173"

    ENABLE_NVD_LIVE_FALLBACK: bool = True
    NVD_API_KEY: str | None = None

    TELEGRAM_BOT_TOKEN: str | None = None
    UPSTASH_REDIS_URL: str | None = None
    UPSTASH_REDIS_TOKEN: str | None = None

    LANGFUSE_PUBLIC_KEY: str | None = None
    LANGFUSE_SECRET_KEY: str | None = None
    LANGFUSE_HOST: str = "https://cloud.langfuse.com"

    LOG_LEVEL: str = "INFO"
    RATE_LIMIT_PER_MINUTE: int = 10
    NVD_RESULTS_PER_PAGE: int = 2000

@lru_cache
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
