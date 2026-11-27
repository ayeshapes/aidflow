"""A small in-process sliding-window rate limiter.

Used for POST /api/auth/login (5 attempts per minute per IP + username).

WHY NOT slowapi? Three reasons, all specific to this endpoint:
  * The limit key must include the USERNAME, which lives in the JSON body.
    slowapi's key function is synchronous and only sees the Request, so it
    cannot read a body that FastAPI has not parsed yet. Here the endpoint
    parses the body first, then calls hit() with the normalised username.
  * slowapi answers with its own response format. We need the standard
    {"error": {...}} shape plus Retry-After, so we would write a custom
    handler anyway.
  * Fewer moving parts to audit: this file is the whole mechanism.

LIMITS (read before relying on it):
  * State lives in this process's memory. It resets on restart, and with N
    uvicorn workers an attacker effectively gets N x the limit. Fine for the
    current single-process deployment; move the counters to Redis (or a DB
    table) before running several workers. The account lockout in
    services/auth.py is stored in the database, so it is NOT affected.
  * Behind a reverse proxy, every request appears to come from the proxy
    unless uvicorn is told which proxy to trust (--forwarded-allow-ips).
    Never read X-Forwarded-For in application code: any client can forge it.
"""
import math
import threading
import time
from collections import deque
from collections.abc import Callable, Hashable


class SlidingWindowLimiter:
    """Allow at most `max_hits` per `window_seconds` for each key.

    Sliding window log: we remember the time of each recent hit. Unlike a
    fixed "per calendar minute" counter, this cannot be gamed by sending 5
    requests at 12:00:59 and 5 more at 12:01:00.
    """

    def __init__(
        self,
        max_hits: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.max_hits = max_hits
        self.window = window_seconds
        self._clock = clock  # injectable so tests need not sleep
        self._hits: dict[Hashable, deque[float]] = {}
        self._next_sweep = 0.0
        # Route handlers run in a thread pool, so the dict needs a lock.
        self._lock = threading.Lock()

    def hit(self, key: Hashable) -> int:
        """Record one attempt for `key`.

        Returns 0 if it is allowed, otherwise the number of whole seconds (at
        least 1) until a slot frees up: the value for a Retry-After header.
        A refused attempt is NOT recorded, so hammering a blocked key does not
        push its release time further away.
        """
        now = self._clock()
        cutoff = now - self.window
        with self._lock:
            if now >= self._next_sweep:
                self._sweep(cutoff)
                self._next_sweep = now + self.window

            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.max_hits:
                return max(1, math.ceil(hits[0] + self.window - now))
            hits.append(now)
            return 0

    def _sweep(self, cutoff: float) -> None:
        """Forget keys with no hit inside the window, so a stream of one-off
        usernames cannot grow the dict forever. Runs at most once per window,
        so the cost is O(keys) per minute, not per request."""
        stale = [k for k, hits in self._hits.items() if not hits or hits[-1] <= cutoff]
        for k in stale:
            del self._hits[k]

    def reset(self) -> None:
        """Forget everything (tests)."""
        with self._lock:
            self._hits.clear()
            self._next_sweep = 0.0


# 5 login attempts per minute for each (client IP, username) pair.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 60
login_limiter = SlidingWindowLimiter(LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS)
