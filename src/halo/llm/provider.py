"""Unified LLM Provider layer supporting Mock, OpenAI, Anthropic, Gemini, and Ollama."""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from typing import Any

import httpx

from halo.llm.governor import TokenGovernor, estimate_tokens

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base class for all HALO LLM providers.

    Coordinates transparent prompt caching and token budgeting through TokenGovernor.
    """

    def __init__(self, governor: TokenGovernor | None = None, model: str = "") -> None:
        self.governor = governor
        self.model = model

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generate a completion for the prompt, respecting token governor limits and caching."""
        if self.governor is not None:
            prompt_hash = self.governor.hash_prompt(prompt, system_prompt)
            cached_response = self.governor.get_cached(prompt_hash)
            if cached_response is not None:
                return cached_response

            # Check budget proactively before calling external model
            if self.governor.remaining_budget() <= 0:
                raise RuntimeError(
                    f"Token budget exceeded: remaining {self.governor.remaining_budget()} tokens"
                )

            response, tokens_in, tokens_out = self._call(prompt, system_prompt)

            # Record consumption and cache response
            self.governor.track_usage(tokens_in, tokens_out)
            self.governor.cache_response(prompt_hash, response)
            return response

        response, _, _ = self._call(prompt, system_prompt)
        return response

    @abstractmethod
    def _call(self, prompt: str, system_prompt: str = "") -> tuple[str, int, int]:
        """Execute underlying LLM call. Returns (response_text, tokens_in, tokens_out)."""


class MockLLMProvider(LLMProvider):
    """Deterministic offline LLM provider with programmable responses, FIFO queue,

    and call history tracking for testing without external API connectivity.
    """

    def __init__(
        self,
        default_response: str = '{"status": "ok"}',
        responses: dict[str, str] | None = None,
        response_queue: list[str] | None = None,
        governor: TokenGovernor | None = None,
        model: str = "mock-model",
    ) -> None:
        super().__init__(governor=governor, model=model)
        self.default_response = default_response
        self.responses = dict(responses) if responses else {}
        self.response_queue = list(response_queue) if response_queue else []
        self.history: list[dict[str, Any]] = []

    def set_response(self, prompt_pattern: str, response: str) -> None:
        """Register a canned response for an exact prompt or substring."""
        self.responses[prompt_pattern] = response

    def queue_response(self, response: str) -> None:
        """Append a response to the FIFO response queue."""
        self.response_queue.append(response)

    @property
    def call_count(self) -> int:
        """Total number of generation calls handled."""
        return len(self.history)

    @property
    def last_call(self) -> dict[str, Any] | None:
        """Details of the most recent generation call, if any."""
        return self.history[-1] if self.history else None

    def _call(self, prompt: str, system_prompt: str = "") -> tuple[str, int, int]:
        # 1. FIFO queue has top precedence
        if self.response_queue:
            response = self.response_queue.pop(0)
        # 2. Exact prompt match
        elif prompt in self.responses:
            response = self.responses[prompt]
        else:
            # 3. Substring match across prompt or system prompt
            matched = False
            for pattern, resp in self.responses.items():
                if pattern in prompt or (system_prompt and pattern in system_prompt):
                    response = resp
                    matched = True
                    break
            # 4. Default fallback
            if not matched:
                response = self.default_response

        tokens_in = estimate_tokens(f"{system_prompt}{prompt}")
        tokens_out = estimate_tokens(response)

        self.history.append(
            {
                "prompt": prompt,
                "system_prompt": system_prompt,
                "response": response,
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
            }
        )
        return response, tokens_in, tokens_out


class OpenAIProvider(LLMProvider):
    """OpenAI API provider adapter using standard HTTP requests."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
        client: httpx.Client | None = None,
        governor: TokenGovernor | None = None,
        timeout: float = 30.0,
        fallback_response: str = '{"status": "ok", "mock": true, "provider": "openai"}',
    ) -> None:
        super().__init__(governor=governor, model=model)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.base_url = (os.getenv("OPENAI_BASE_URL") or base_url).rstrip("/")
        self.client = client
        self.timeout = timeout
        self.fallback_response = fallback_response
        self.offline_mode = not bool(self.api_key)

    def _call(self, prompt: str, system_prompt: str = "") -> tuple[str, int, int]:
        if self.offline_mode or not self.api_key:
            logger.info("OpenAIProvider running in offline fallback mode")
            return (
                self.fallback_response,
                estimate_tokens(f"{system_prompt}{prompt}"),
                estimate_tokens(self.fallback_response),
            )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.0,
        }

        try:
            if self.client is not None:
                resp = self.client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                )
            else:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(
                        f"{self.base_url}/chat/completions",
                        json=payload,
                        headers=headers,
                    )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            tokens_in = usage.get("prompt_tokens", estimate_tokens(f"{system_prompt}{prompt}"))
            tokens_out = usage.get("completion_tokens", estimate_tokens(content))
            return content, tokens_in, tokens_out
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            logger.warning("OpenAI API request failed: %s; falling back to offline mode", exc)
            return (
                self.fallback_response,
                estimate_tokens(f"{system_prompt}{prompt}"),
                estimate_tokens(self.fallback_response),
            )


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider adapter using standard HTTP requests."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-3-5-sonnet-20241022",
        base_url: str = "https://api.anthropic.com/v1",
        client: httpx.Client | None = None,
        governor: TokenGovernor | None = None,
        timeout: float = 30.0,
        fallback_response: str = '{"status": "ok", "mock": true, "provider": "anthropic"}',
    ) -> None:
        super().__init__(governor=governor, model=model)
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.base_url = (os.getenv("ANTHROPIC_BASE_URL") or base_url).rstrip("/")
        self.client = client
        self.timeout = timeout
        self.fallback_response = fallback_response
        self.offline_mode = not bool(self.api_key)

    def _call(self, prompt: str, system_prompt: str = "") -> tuple[str, int, int]:
        if self.offline_mode or not self.api_key:
            logger.info("AnthropicProvider running in offline fallback mode")
            return (
                self.fallback_response,
                estimate_tokens(f"{system_prompt}{prompt}"),
                estimate_tokens(self.fallback_response),
            )

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            if self.client is not None:
                resp = self.client.post(
                    f"{self.base_url}/messages",
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                )
            else:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(
                        f"{self.base_url}/messages",
                        json=payload,
                        headers=headers,
                    )
            resp.raise_for_status()
            data = resp.json()
            content = data["content"][0]["text"]
            usage = data.get("usage", {})
            tokens_in = usage.get("input_tokens", estimate_tokens(f"{system_prompt}{prompt}"))
            tokens_out = usage.get("output_tokens", estimate_tokens(content))
            return content, tokens_in, tokens_out
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            logger.warning("Anthropic API request failed: %s; falling back to offline mode", exc)
            return (
                self.fallback_response,
                estimate_tokens(f"{system_prompt}{prompt}"),
                estimate_tokens(self.fallback_response),
            )


class GeminiProvider(LLMProvider):
    """Google Gemini API provider adapter using standard REST HTTP requests."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-1.5-flash",
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        client: httpx.Client | None = None,
        governor: TokenGovernor | None = None,
        timeout: float = 30.0,
        fallback_response: str = '{"status": "ok", "mock": true, "provider": "gemini"}',
    ) -> None:
        super().__init__(governor=governor, model=model)
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.base_url = (os.getenv("GEMINI_BASE_URL") or base_url).rstrip("/")
        self.client = client
        self.timeout = timeout
        self.fallback_response = fallback_response
        self.offline_mode = not bool(self.api_key)

    def _call(self, prompt: str, system_prompt: str = "") -> tuple[str, int, int]:
        if self.offline_mode or not self.api_key:
            logger.info("GeminiProvider running in offline fallback mode")
            return (
                self.fallback_response,
                estimate_tokens(f"{system_prompt}{prompt}"),
                estimate_tokens(self.fallback_response),
            )

        payload: dict[str, Any] = {
            "contents": [{"parts": [{"text": prompt}]}],
        }
        if system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}

        url = f"{self.base_url}/models/{self.model}:generateContent"
        params = {"key": self.api_key}

        try:
            if self.client is not None:
                resp = self.client.post(
                    url,
                    params=params,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
            else:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(
                        url,
                        params=params,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )
            resp.raise_for_status()
            data = resp.json()
            content = data["candidates"][0]["content"]["parts"][0]["text"]
            usage = data.get("usageMetadata", {})
            tokens_in = usage.get(
                "promptTokenCount", estimate_tokens(f"{system_prompt}{prompt}")
            )
            tokens_out = usage.get("candidatesTokenCount", estimate_tokens(content))
            return content, tokens_in, tokens_out
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            logger.warning("Gemini API request failed: %s; falling back to offline mode", exc)
            return (
                self.fallback_response,
                estimate_tokens(f"{system_prompt}{prompt}"),
                estimate_tokens(self.fallback_response),
            )


class OllamaProvider(LLMProvider):
    """Local Ollama provider adapter using HTTP requests to local/remote Ollama daemon."""

    def __init__(
        self,
        host: str | None = None,
        model: str = "llama3",
        client: httpx.Client | None = None,
        governor: TokenGovernor | None = None,
        timeout: float = 30.0,
        fallback_response: str = '{"status": "ok", "mock": true, "provider": "ollama"}',
    ) -> None:
        super().__init__(governor=governor, model=model)
        self.host = (host or os.getenv("OLLAMA_HOST") or "http://localhost:11434").rstrip("/")
        self.client = client
        self.timeout = timeout
        self.fallback_response = fallback_response

    def _call(self, prompt: str, system_prompt: str = "") -> tuple[str, int, int]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }

        try:
            if self.client is not None:
                resp = self.client.post(
                    f"{self.host}/api/chat",
                    json=payload,
                    timeout=self.timeout,
                )
            else:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(
                        f"{self.host}/api/chat",
                        json=payload,
                    )
            resp.raise_for_status()
            data = resp.json()
            content = data["message"]["content"]
            tokens_in = data.get(
                "prompt_eval_count", estimate_tokens(f"{system_prompt}{prompt}")
            )
            tokens_out = data.get("eval_count", estimate_tokens(content))
            return content, tokens_in, tokens_out
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            logger.warning("Ollama connection failed: %s; falling back to offline mode", exc)
            return (
                self.fallback_response,
                estimate_tokens(f"{system_prompt}{prompt}"),
                estimate_tokens(self.fallback_response),
            )


def get_llm_provider(
    provider_type: str = "mock",
    governor: TokenGovernor | None = None,
    **kwargs: Any,
) -> LLMProvider:
    """Factory creating an LLMProvider instance with transparent offline/mock fallbacks."""
    p_type = provider_type.lower().strip()

    if p_type == "mock":
        return MockLLMProvider(governor=governor, **kwargs)

    if p_type == "openai":
        api_key = kwargs.get("api_key") or os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.info("OPENAI_API_KEY not found; falling back to MockLLMProvider")
            default_resp = kwargs.pop(
                "default_response", '{"mock": true, "provider": "openai"}'
            )
            return MockLLMProvider(governor=governor, default_response=default_resp, **kwargs)
        return OpenAIProvider(governor=governor, **kwargs)

    if p_type == "anthropic":
        api_key = kwargs.get("api_key") or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            logger.info("ANTHROPIC_API_KEY not found; falling back to MockLLMProvider")
            default_resp = kwargs.pop(
                "default_response", '{"mock": true, "provider": "anthropic"}'
            )
            return MockLLMProvider(governor=governor, default_response=default_resp, **kwargs)
        return AnthropicProvider(governor=governor, **kwargs)

    if p_type == "gemini":
        api_key = kwargs.get("api_key") or os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.info("GEMINI_API_KEY not found; falling back to MockLLMProvider")
            default_resp = kwargs.pop(
                "default_response", '{"mock": true, "provider": "gemini"}'
            )
            return MockLLMProvider(governor=governor, default_response=default_resp, **kwargs)
        return GeminiProvider(governor=governor, **kwargs)

    if p_type == "ollama":
        return OllamaProvider(governor=governor, **kwargs)

    if p_type == "auto":
        if os.getenv("OPENAI_API_KEY"):
            return OpenAIProvider(governor=governor, **kwargs)
        if os.getenv("ANTHROPIC_API_KEY"):
            return AnthropicProvider(governor=governor, **kwargs)
        if os.getenv("GEMINI_API_KEY"):
            return GeminiProvider(governor=governor, **kwargs)
        if os.getenv("OLLAMA_HOST"):
            return OllamaProvider(governor=governor, **kwargs)
        logger.info("No LLM credentials found in environment; auto-selecting MockLLMProvider")
        return MockLLMProvider(governor=governor, **kwargs)

    raise ValueError(
        f"Unknown provider type '{provider_type}'. Supported types: "
        "'mock', 'openai', 'anthropic', 'gemini', 'ollama', 'auto'"
    )
