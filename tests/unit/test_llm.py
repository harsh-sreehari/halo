"""Unit tests for halo.llm.governor and halo.llm.provider."""

import json
import os
import time
from unittest.mock import patch

import httpx
import pytest

from halo.llm.governor import TokenGovernor, TokenUsageStats, estimate_tokens
from halo.llm.provider import (
    AnthropicProvider,
    GeminiProvider,
    MockLLMProvider,
    OllamaProvider,
    OpenAIProvider,
    get_llm_provider,
)

# ---------------------------------------------------------------------------
# TokenGovernor Tests
# ---------------------------------------------------------------------------


def test_token_governor_budget_limit():
    gov = TokenGovernor(max_budget=1000)
    gov.track_usage(600, 200)
    assert gov.remaining_budget() == 200
    with pytest.raises(RuntimeError, match="Token budget exceeded"):
        gov.track_usage(300, 50)


def test_token_governor_default_budget():
    gov = TokenGovernor()
    assert gov.max_budget == 150_000
    assert gov.remaining_budget() == 150_000


def test_token_governor_cache():
    gov = TokenGovernor(max_budget=1000)
    prompt = "SELECT * FROM users;"
    system_prompt = "You are a code analyzer."
    prompt_hash = gov.hash_prompt(prompt, system_prompt)

    # Initially cache miss
    assert gov.get_cached(prompt_hash) is None
    stats = gov.get_stats()
    assert stats.cache_misses == 1
    assert stats.cache_hits == 0

    # Cache response
    gov.cache_response(prompt_hash, '{"safe": false}')
    cached = gov.get_cached(prompt_hash)
    assert cached == '{"safe": false}'

    stats = gov.get_stats()
    assert stats.cache_hits == 1


def test_token_governor_pydantic_stats():
    gov = TokenGovernor(max_budget=5000)
    gov.track_usage(100, 50)
    gov.track_usage(200, 100)

    stats = gov.get_stats()
    assert isinstance(stats, TokenUsageStats)
    assert stats.total_input_tokens == 300
    assert stats.total_output_tokens == 150
    assert stats.total_tokens == 450
    assert stats.max_budget == 5000
    assert stats.remaining_budget == 4550
    assert stats.request_count == 2

    # Test serialization
    dumped = stats.model_dump()
    assert dumped["total_tokens"] == 450
    assert dumped["remaining_budget"] == 4550


def test_token_governor_negative_input_validation():
    gov = TokenGovernor(max_budget=1000)
    with pytest.raises(ValueError, match="non-negative"):
        gov.track_usage(-10, 50)
    with pytest.raises(ValueError, match="non-negative"):
        gov.track_usage(50, -10)


def test_token_governor_sliding_window_rate_limiter():
    gov = TokenGovernor(
        max_budget=10_000,
        max_requests_per_minute=2,
        window_seconds=0.2,
    )
    gov.track_usage(10, 10)
    gov.track_usage(10, 10)

    # 3rd request inside window should trigger rate limit error
    with pytest.raises(RuntimeError, match="Rate limit exceeded"):
        gov.track_usage(10, 10)

    # After window passes, request succeeds
    time.sleep(0.25)
    gov.track_usage(10, 10)
    assert gov.remaining_budget() == 9940


def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("short") > 0
    text_100_chars = "a" * 100
    # ~25 tokens for 100 chars
    assert 20 <= estimate_tokens(text_100_chars) <= 30


# ---------------------------------------------------------------------------
# MockLLMProvider Tests
# ---------------------------------------------------------------------------


def test_mock_llm_provider_offline():
    provider = MockLLMProvider(default_response='{"status": "ok"}')
    res = provider.generate("Test prompt")
    assert res == '{"status": "ok"}'


def test_mock_llm_provider_programmable_responses():
    provider = MockLLMProvider(
        default_response='{"type": "default"}',
        responses={
            "auth": '{"type": "auth_policy"}',
            "exact prompt": '{"type": "exact"}',
        },
        response_queue=['{"type": "queued_1"}', '{"type": "queued_2"}'],
    )

    # 1. Queue has priority
    assert provider.generate("anything") == '{"type": "queued_1"}'
    assert provider.generate("anything") == '{"type": "queued_2"}'

    # 2. Queue empty -> exact match
    assert provider.generate("exact prompt") == '{"type": "exact"}'

    # 3. Substring match
    assert provider.generate("check authentication logic") == '{"type": "auth_policy"}'

    # 4. Default fallback
    assert provider.generate("something else entirely") == '{"type": "default"}'

    # Dynamic additions
    provider.queue_response('{"type": "queued_3"}')
    assert provider.generate("whatever") == '{"type": "queued_3"}'

    provider.set_response("new_pattern", '{"type": "new_pattern"}')
    assert provider.generate("has new_pattern inside") == '{"type": "new_pattern"}'

    assert provider.call_count == 7
    assert len(provider.history) == 7
    assert provider.last_call["prompt"] == "has new_pattern inside"


def test_provider_with_governor_and_caching():
    gov = TokenGovernor(max_budget=10_000)
    provider = MockLLMProvider(default_response='{"verdict": "vulnerable"}', governor=gov)

    # First call: hits provider and tracks tokens in governor
    resp1 = provider.generate("analyze function foo", system_prompt="security analyst")
    assert resp1 == '{"verdict": "vulnerable"}'

    stats1 = gov.get_stats()
    assert stats1.request_count == 1
    assert stats1.cache_hits == 0
    assert stats1.remaining_budget < 10_000
    rem_budget_after_first = stats1.remaining_budget

    # Second call with identical prompt + system_prompt: served from cache!
    resp2 = provider.generate("analyze function foo", system_prompt="security analyst")
    assert resp2 == '{"verdict": "vulnerable"}'

    stats2 = gov.get_stats()
    # Cache hit should NOT consume additional tokens or increment request_count
    assert stats2.cache_hits == 1
    assert stats2.remaining_budget == rem_budget_after_first


def test_provider_exceeds_token_budget():
    gov = TokenGovernor(max_budget=50)
    long_response = "X" * 1000  # ~250 tokens
    provider = MockLLMProvider(default_response=long_response, governor=gov)

    with pytest.raises(RuntimeError, match="Token budget exceeded"):
        provider.generate("Analyze this")


# ---------------------------------------------------------------------------
# Provider Adapters Tests (with Mocked Transports)
# ---------------------------------------------------------------------------


def test_openai_provider_with_mock_transport():
    captured_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == "gpt-4o-mini"
        assert body["messages"][0] == {"role": "system", "content": "system instruction"}
        assert body["messages"][1] == {"role": "user", "content": "user query"}
        assert request.headers["authorization"] == "Bearer test-sk-openai"

        return httpx.Response(
            status_code=200,
            json={
                "choices": [{"message": {"content": '{"analysis": "idor_found"}'}}],
                "usage": {"prompt_tokens": 40, "completion_tokens": 15},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    gov = TokenGovernor(max_budget=5000)
    provider = OpenAIProvider(api_key="test-sk-openai", client=client, governor=gov)

    resp = provider.generate("user query", system_prompt="system instruction")
    assert resp == '{"analysis": "idor_found"}'
    assert len(captured_requests) == 1

    stats = gov.get_stats()
    assert stats.total_input_tokens == 40
    assert stats.total_output_tokens == 15
    assert stats.total_tokens == 55


def test_anthropic_provider_with_mock_transport():
    captured_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == "claude-3-5-sonnet-20241022"
        assert body["system"] == "system instruction"
        assert body["messages"][0] == {"role": "user", "content": "user query"}
        assert request.headers["x-api-key"] == "test-sk-ant"

        return httpx.Response(
            status_code=200,
            json={
                "content": [{"text": '{"analysis": "bola_detected"}'}],
                "usage": {"input_tokens": 50, "output_tokens": 20},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    gov = TokenGovernor(max_budget=5000)
    provider = AnthropicProvider(api_key="test-sk-ant", client=client, governor=gov)

    resp = provider.generate("user query", system_prompt="system instruction")
    assert resp == '{"analysis": "bola_detected"}'
    assert len(captured_requests) == 1

    stats = gov.get_stats()
    assert stats.total_input_tokens == 50
    assert stats.total_output_tokens == 20
    assert stats.total_tokens == 70


def test_gemini_provider_with_mock_transport():
    captured_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        assert request.url.params["key"] == "test-gemini-key"
        body = json.loads(request.content.decode("utf-8"))
        assert body["contents"][0]["parts"][0]["text"] == "user query"
        assert body["systemInstruction"]["parts"][0]["text"] == "system instruction"

        return httpx.Response(
            status_code=200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": '{"analysis": "broken_object_level_auth"}'}]
                        }
                    }
                ],
                "usageMetadata": {"promptTokenCount": 60, "candidatesTokenCount": 25},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    gov = TokenGovernor(max_budget=5000)
    provider = GeminiProvider(api_key="test-gemini-key", client=client, governor=gov)

    resp = provider.generate("user query", system_prompt="system instruction")
    assert resp == '{"analysis": "broken_object_level_auth"}'
    assert len(captured_requests) == 1

    stats = gov.get_stats()
    assert stats.total_input_tokens == 60
    assert stats.total_output_tokens == 25


def test_ollama_provider_with_mock_transport():
    captured_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == "llama3"
        assert body["messages"][0] == {"role": "system", "content": "system instruction"}
        assert body["messages"][1] == {"role": "user", "content": "user query"}
        assert body["stream"] is False

        return httpx.Response(
            status_code=200,
            json={
                "message": {"content": '{"analysis": "ssrf_candidate"}'},
                "prompt_eval_count": 45,
                "eval_count": 18,
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    gov = TokenGovernor(max_budget=5000)
    provider = OllamaProvider(host="http://localhost:11434", client=client, governor=gov)

    resp = provider.generate("user query", system_prompt="system instruction")
    assert resp == '{"analysis": "ssrf_candidate"}'
    assert len(captured_requests) == 1

    stats = gov.get_stats()
    assert stats.total_input_tokens == 45
    assert stats.total_output_tokens == 18


def test_provider_adapters_fallback_when_keys_absent():
    with patch.dict(os.environ, {}, clear=True):
        # When keys are absent, providers should fallback gracefully without raising
        p_openai = OpenAIProvider()
        res_openai = p_openai.generate("test")
        assert "mock" in res_openai or "offline" in res_openai.lower() or "status" in res_openai

        p_anthropic = AnthropicProvider()
        res_anthropic = p_anthropic.generate("test")
        assert "mock" in res_anthropic or "offline" in res_anthropic.lower() or "status" in res_anthropic

        p_gemini = GeminiProvider()
        res_gemini = p_gemini.generate("test")
        assert "mock" in res_gemini or "offline" in res_gemini.lower() or "status" in res_gemini


def test_ollama_unreachable_fallback():
    # If Ollama server is unreachable, it should fall back to offline mode
    def error_handler(request: httpx.Request):
        raise httpx.ConnectError("Connection refused")

    client = httpx.Client(transport=httpx.MockTransport(error_handler))
    provider = OllamaProvider(host="http://localhost:9999", client=client)
    res = provider.generate("test")
    assert "mock" in res or "offline" in res.lower() or "status" in res


# ---------------------------------------------------------------------------
# Provider Factory Tests
# ---------------------------------------------------------------------------


def test_get_llm_provider_factory():
    gov = TokenGovernor(max_budget=2000)

    # 1. Mock provider
    p_mock = get_llm_provider("mock", governor=gov)
    assert isinstance(p_mock, MockLLMProvider)
    assert p_mock.governor is gov

    # 2. OpenAI with key vs absent
    with patch.dict(os.environ, {}, clear=True):
        p_openai_absent = get_llm_provider("openai")
        # Falls back to MockLLMProvider when key is absent
        assert isinstance(p_openai_absent, MockLLMProvider)

        p_openai_with_key = get_llm_provider("openai", api_key="sk-explicit")
        assert isinstance(p_openai_with_key, OpenAIProvider)

    # 3. Anthropic with key vs absent
    with patch.dict(os.environ, {}, clear=True):
        p_anthropic_absent = get_llm_provider("anthropic")
        assert isinstance(p_anthropic_absent, MockLLMProvider)

        p_anthropic_with_key = get_llm_provider("anthropic", api_key="sk-ant-explicit")
        assert isinstance(p_anthropic_with_key, AnthropicProvider)

    # 4. Gemini with key vs absent
    with patch.dict(os.environ, {}, clear=True):
        p_gemini_absent = get_llm_provider("gemini")
        assert isinstance(p_gemini_absent, MockLLMProvider)

        p_gemini_with_key = get_llm_provider("gemini", api_key="gemini-explicit")
        assert isinstance(p_gemini_with_key, GeminiProvider)

    # 5. Ollama
    p_ollama = get_llm_provider("ollama")
    assert isinstance(p_ollama, OllamaProvider)

    # 6. Auto selection
    with patch.dict(os.environ, {}, clear=True):
        p_auto_default = get_llm_provider("auto")
        assert isinstance(p_auto_default, MockLLMProvider)

    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-mock-env"}):
        p_auto_openai = get_llm_provider("auto")
        assert isinstance(p_auto_openai, OpenAIProvider)

    # 7. Invalid provider raises ValueError
    with pytest.raises(ValueError, match="Unknown provider type"):
        get_llm_provider("unsupported_provider_type")
