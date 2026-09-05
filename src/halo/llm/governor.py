"""Token Governor subsystem for tracking LLM token consumption and enforcing scan ceilings."""

from __future__ import annotations

import hashlib
import time
from collections import deque

from pydantic import BaseModel, Field


def estimate_tokens(text: str) -> int:
    """Estimate token count for a text string using standard ~4 chars/token heuristic."""
    if not text:
        return 0
    # Standard heuristic: 1 token ~= 4 characters; min 1 token for non-empty text
    return max(1, (len(text) + 3) // 4)


class TokenUsageStats(BaseModel):
    """Pydantic model representing token consumption statistics and governor status."""

    total_input_tokens: int = Field(default=0, description="Total input tokens consumed")
    total_output_tokens: int = Field(default=0, description="Total output tokens consumed")
    total_tokens: int = Field(default=0, description="Total tokens consumed across all calls")
    max_budget: int = Field(default=150_000, description="Strict maximum token ceiling for scan")
    remaining_budget: int = Field(
        default=150_000, description="Remaining tokens before budget exhaustion"
    )
    request_count: int = Field(default=0, description="Total number of non-cached LLM requests")
    cache_hits: int = Field(default=0, description="Number of requests served from prompt cache")
    cache_misses: int = Field(default=0, description="Number of cache misses")


class TokenGovernor:
    """Tracks token consumption against a maximum budget, enforces sliding-window rate limits,

    and caches prompt responses to prevent redundant LLM invocations.
    """

    def __init__(
        self,
        max_budget: int = 150_000,
        max_requests_per_minute: int | None = None,
        max_tokens_per_minute: int | None = None,
        window_seconds: float = 60.0,
    ) -> None:
        if max_budget <= 0:
            raise ValueError(f"max_budget must be positive, got {max_budget}")
        self.max_budget = max_budget
        self.max_requests_per_minute = max_requests_per_minute
        self.max_tokens_per_minute = max_tokens_per_minute
        self.window_seconds = window_seconds

        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_tokens = 0
        self.request_count = 0
        self._cache_hits = 0
        self._cache_misses = 0

        # SHA-256 prompt response cache: hash -> response
        self._cache: dict[str, str] = {}

        # Sliding window timestamp queues
        self._request_timestamps: deque[float] = deque()
        self._token_timestamps: deque[tuple[float, int]] = deque()

    @staticmethod
    def hash_prompt(prompt: str, system_prompt: str = "") -> str:
        """Compute deterministic SHA-256 hex digest for (system_prompt + prompt)."""
        content = f"{system_prompt}{prompt}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def remaining_budget(self) -> int:
        """Return remaining tokens available within the scan budget."""
        return max(0, self.max_budget - self.total_tokens)

    def _purge_window(self, now: float) -> None:
        """Remove timestamps outside the current sliding time window."""
        cutoff = now - self.window_seconds
        while self._request_timestamps and self._request_timestamps[0] < cutoff:
            self._request_timestamps.popleft()
        while self._token_timestamps and self._token_timestamps[0][0] < cutoff:
            self._token_timestamps.popleft()

    def check_rate_limit(self, projected_tokens: int = 0) -> None:
        """Verify if current call conforms to sliding-window rate limits.

        Raises RuntimeError if rate limit is exceeded.
        """
        now = time.time()
        self._purge_window(now)

        if (
            self.max_requests_per_minute is not None
            and len(self._request_timestamps) >= self.max_requests_per_minute
        ):
            raise RuntimeError(
                f"Rate limit exceeded: {len(self._request_timestamps)} requests in last "
                f"{self.window_seconds}s (limit: {self.max_requests_per_minute})"
            )

        if self.max_tokens_per_minute is not None:
            current_tokens = sum(tokens for _, tokens in self._token_timestamps)
            if current_tokens + projected_tokens > self.max_tokens_per_minute:
                raise RuntimeError(
                    f"Rate limit exceeded: {current_tokens + projected_tokens} tokens in last "
                    f"{self.window_seconds}s (limit: {self.max_tokens_per_minute})"
                )

    def track_usage(self, tokens_in: int, tokens_out: int) -> None:
        """Record token consumption from an LLM call.

        Enforces rate limits and overall scan budget.
        Raises ValueError if token counts are negative.
        Raises RuntimeError if budget or rate limits are exceeded.
        """
        if tokens_in < 0 or tokens_out < 0:
            raise ValueError(
                f"Token counts must be non-negative, got in={tokens_in}, out={tokens_out}"
            )

        tokens_called = tokens_in + tokens_out
        new_total = self.total_tokens + tokens_called

        # 1. Budget enforcement: raises before updating counts
        if new_total > self.max_budget:
            raise RuntimeError(
                f"Token budget exceeded: attempting to use {tokens_called} tokens, "
                f"remaining budget is {self.remaining_budget()} (max: {self.max_budget})"
            )

        # 2. Rate limit enforcement
        self.check_rate_limit(projected_tokens=tokens_called)

        # 3. Update state
        now = time.time()
        self.total_input_tokens += tokens_in
        self.total_output_tokens += tokens_out
        self.total_tokens = new_total
        self.request_count += 1

        self._request_timestamps.append(now)
        self._token_timestamps.append((now, tokens_called))

    def get_cached(self, prompt_hash: str) -> str | None:
        """Retrieve cached response if available, updating hit/miss statistics."""
        if prompt_hash in self._cache:
            self._cache_hits += 1
            return self._cache[prompt_hash]
        self._cache_misses += 1
        return None

    def cache_response(self, prompt_hash: str, response: str) -> None:
        """Store prompt response in the SHA-256 keyed cache."""
        self._cache[prompt_hash] = response

    def clear_cache(self) -> None:
        """Clear all cached responses."""
        self._cache.clear()

    def get_stats(self) -> TokenUsageStats:
        """Return a snapshot of token usage and governor statistics."""
        return TokenUsageStats(
            total_input_tokens=self.total_input_tokens,
            total_output_tokens=self.total_output_tokens,
            total_tokens=self.total_tokens,
            max_budget=self.max_budget,
            remaining_budget=self.remaining_budget(),
            request_count=self.request_count,
            cache_hits=self._cache_hits,
            cache_misses=self._cache_misses,
        )

    @property
    def stats(self) -> TokenUsageStats:
        """Convenience property accessing current token stats."""
        return self.get_stats()
