import asyncio
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window limits for sensitive endpoints; Redis is shared across workers."""

    def __init__(self, app):
        super().__init__(app)
        self._local_hits = defaultdict(deque)
        self._local_lock = asyncio.Lock()
        self._redis = None

    @staticmethod
    def _policy(path: str):
        if path in {"/api/auth/login", "/api/auth/register"}:
            return "auth", 10, 300
        if path in {"/api/analysis/source-zip", "/api/analysis/website"}:
            return "analysis", 5, 600
        return None

    async def _allow_local(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()
        async with self._local_lock:
            hits = self._local_hits[key]
            while hits and hits[0] <= now - window:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    async def _allow_redis(self, key: str, limit: int, window: int) -> bool:
        if self._redis is None:
            from redis.asyncio import Redis
            self._redis = Redis.from_url(settings.redis_url, decode_responses=True)
        pipe = self._redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, window)
        result = await pipe.execute()
        return int(result[0]) <= limit

    async def dispatch(self, request: Request, call_next):
        policy = self._policy(request.url.path)
        if policy is None or request.method != "POST":
            return await call_next(request)

        category, limit, window = policy
        client_ip = request.client.host if request.client else "unknown"
        key = f"vulnscan:rate:{category}:{client_ip}"

        try:
            if settings.redis_url:
                allowed = await self._allow_redis(key, limit, window)
            elif settings.app_env.lower() == "production":
                return JSONResponse(status_code=503, content={"detail": "Rate limiting Redis não configurado."})
            else:
                allowed = await self._allow_local(key, limit, window)
        except Exception:
            if settings.app_env.lower() == "production":
                return JSONResponse(status_code=503, content={"detail": "Serviço de proteção contra abuso indisponível."})
            allowed = await self._allow_local(key, limit, window)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Limite de requisições atingido. Tente novamente mais tarde."},
                headers={"Retry-After": str(window)},
            )
        return await call_next(request)
