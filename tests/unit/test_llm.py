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
    NvidiaProvider,
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


def test_token_governor_prompt_hash_delimiter_collision_prevention():
    # Null byte delimiter ensures different prompt/system_prompt boundaries produce different hashes
    hash1 = TokenGovernor.hash_prompt(prompt="bc", system_prompt="a")
    hash2 = TokenGovernor.hash_prompt(prompt="c", system_prompt="ab")
    assert hash1 != hash2

    # Empty system prompt handled cleanly
    hash3 = TokenGovernor.hash_prompt(prompt="abc", system_prompt="")
    assert hash3 != hash1
    assert hash3 != hash2


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


def test_live_adapters_raise_http_errors_by_default():
    # When keys are provided and fallback_on_error is False (default), HTTP errors must re-raise

    # 1. OpenAI 401 Unauthorized
    def openai_err(req: httpx.Request):
        return httpx.Response(status_code=401, text="Unauthorized: Invalid API Key")

    client_openai = httpx.Client(transport=httpx.MockTransport(openai_err))
    p_openai = OpenAIProvider(api_key="sk-invalid", client=client_openai, fallback_on_error=False)
    with pytest.raises(httpx.HTTPStatusError):
        p_openai.generate("test prompt")

    # 2. Anthropic 500 Internal Server Error
    def anthropic_err(req: httpx.Request):
        return httpx.Response(status_code=500, text="Internal Server Error")

    client_ant = httpx.Client(transport=httpx.MockTransport(anthropic_err))
    p_ant = AnthropicProvider(api_key="sk-ant-test", client=client_ant, fallback_on_error=False)
    with pytest.raises(httpx.HTTPStatusError):
        p_ant.generate("test prompt")

    # 3. Gemini 429 Rate Limited
    def gemini_err(req: httpx.Request):
        return httpx.Response(status_code=429, text="Resource Exhausted")

    client_gem = httpx.Client(transport=httpx.MockTransport(gemini_err))
    p_gem = GeminiProvider(api_key="gem-test", client=client_gem, fallback_on_error=False)
    with pytest.raises(httpx.HTTPStatusError):
        p_gem.generate("test prompt")

    # 4. Ollama ConnectError
    def ollama_err(req: httpx.Request):
        raise httpx.ConnectError("Connection refused")

    client_ollama = httpx.Client(transport=httpx.MockTransport(ollama_err))
    p_ollama = OllamaProvider(host="http://localhost:9999", client=client_ollama, fallback_on_error=False)
    with pytest.raises(httpx.ConnectError):
        p_ollama.generate("test prompt")


def test_live_adapters_fallback_when_fallback_on_error_true():
    # When fallback_on_error is explicitly True, errors return fallback responses without raising

    def err_handler(req: httpx.Request):
        return httpx.Response(status_code=500, text="Server Error")

    client = httpx.Client(transport=httpx.MockTransport(err_handler))

    p_openai = OpenAIProvider(api_key="sk-test", client=client, fallback_on_error=True)
    assert "mock" in p_openai.generate("test")

    p_ant = AnthropicProvider(api_key="sk-ant-test", client=client, fallback_on_error=True)
    assert "mock" in p_ant.generate("test")

    p_gem = GeminiProvider(api_key="gem-test", client=client, fallback_on_error=True)
    assert "mock" in p_gem.generate("test")

    def conn_err(req: httpx.Request):
        raise httpx.ConnectError("Connection failed")

    client_conn = httpx.Client(transport=httpx.MockTransport(conn_err))
    p_ollama = OllamaProvider(host="http://localhost:9999", client=client_conn, fallback_on_error=True)
    assert "mock" in p_ollama.generate("test")


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

        p_openai_with_key = get_llm_provider("openai", api_key="sk-explicit", fallback_on_error=True)
        assert isinstance(p_openai_with_key, OpenAIProvider)
        assert p_openai_with_key.fallback_on_error is True

    # 3. Anthropic with key vs absent
    with patch.dict(os.environ, {}, clear=True):
        p_anthropic_absent = get_llm_provider("anthropic")
        assert isinstance(p_anthropic_absent, MockLLMProvider)

        p_anthropic_with_key = get_llm_provider("anthropic", api_key="sk-ant-explicit")
        assert isinstance(p_anthropic_with_key, AnthropicProvider)
        assert p_anthropic_with_key.fallback_on_error is False

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

    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-mock-env"}, clear=True):
        p_auto_openai = get_llm_provider("auto")
        assert isinstance(p_auto_openai, OpenAIProvider)

    # 7. Nvidia provider with key vs absent
    with patch.dict(os.environ, {}, clear=True):
        p_nvidia_absent = get_llm_provider("nvidia")
        assert isinstance(p_nvidia_absent, MockLLMProvider)

        p_nvidia_with_key = get_llm_provider("nvidia", api_key="nvapi-test")
        assert isinstance(p_nvidia_with_key, NvidiaProvider)
        assert p_nvidia_with_key.base_url == "https://integrate.api.nvidia.com/v1"
        assert p_nvidia_with_key.model == "nvidia/nemotron-3-super-120b-a12b"

    with patch.dict(os.environ, {"NVIDIA_API_KEY": "nvapi-test-env"}, clear=True):
        p_auto_nvidia = get_llm_provider("auto")
        assert isinstance(p_auto_nvidia, NvidiaProvider)

    # 8. Invalid provider raises ValueError
    with pytest.raises(ValueError, match="Unknown provider type"):
        get_llm_provider("unsupported_provider_type")


def test_nvidia_provider_call():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://integrate.api.nvidia.com/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer nvapi-123"
        body = json.loads(request.read().decode("utf-8"))
        assert body["model"] == "nvidia/nemotron-3-super-120b-a12b"
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"analysis": "tested"}'}}],
                "usage": {"prompt_tokens": 15, "completion_tokens": 8},
            },
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    provider = NvidiaProvider(api_key="nvapi-123", client=client)
    res = provider.generate("Test prompt")
    assert res == '{"analysis": "tested"}'


def test_token_governor_wait_for_rate_limit():
    gov = TokenGovernor(max_budget=10000, max_requests_per_minute=2, window_seconds=0.2)
    t0 = time.time()
    gov.track_usage(10, 10)
    gov.track_usage(10, 10)
    # Third request should trigger wait_for_rate_limit until window expires
    gov.wait_for_rate_limit(projected_tokens=20)
    elapsed = time.time() - t0
    assert elapsed >= 0.15
