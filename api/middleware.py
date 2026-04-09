import time
from fastapi import Header, HTTPException, Request
from redis import Redis
from config import settings

class RateLimiter:
    def __init__(self) -> None:
        self.redis_client = None
        self.memory_store: dict[str, list[float]] = {}
        if settings.UPSTASH_REDIS_URL:
            try:
                self.redis_client = Redis.from_url(settings.UPSTASH_REDIS_URL, decode_responses=True)
            except Exception:
                self.redis_client = None

    def allow(self, key: str, limit: int) -> None:
        if self.redis_client is not None:
            try:
                count = self.redis_client.incr(key)
                if count == 1:
                    self.redis_client.expire(key, 60)
                if count > limit:
                    raise HTTPException(status_code=429, detail="Rate limit exceeded")
                return
            except HTTPException:
                raise
            except Exception:
                pass

        now = time.time()
        bucket = self.memory_store.setdefault(key, [])
        bucket[:] = [ts for ts in bucket if now - ts <= 60]
        if len(bucket) >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        bucket.append(now)

rate_limiter = RateLimiter()

def validate_api_key(x_api_key: str | None = Header(default=None)) -> str:
    if x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

def enforce_rate_limit(request: Request) -> None:
    client_host = request.client.host if request.client else "unknown"
    rate_limiter.allow(f"rl:{client_host}", settings.RATE_LIMIT_PER_MINUTE)
