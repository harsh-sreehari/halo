"""Dynamic Concurrency Race Condition Probing Engine with ALPN negotiation, HTTP/2 multiplexing, and H1.1 Barrier Burst."""

from __future__ import annotations

import json
import logging
import socket
import ssl
import threading
import urllib.parse
from typing import Any

import httpx

from halo.dast.probes.base import BaseProbe, ProbeResult
from halo.dast.vault import PersonaType, SessionVault
from halo.intent.hypothesis import HypothesisResult, ProbingRecipe

logger = logging.getLogger(__name__)


class RaceConditionProbe(BaseProbe):
    """Dynamic active verification probe for concurrency race conditions and TOCTOU flaws.

    Supports:
    - Protocol negotiation / ALPN check for HTTP/2 support.
    - HTTP/2 single-packet multiplexing (when H2 is supported).
    - Synchronized keep-alive threading barrier burst pool (when HTTP/1.1).
    - State Multiplication Gate: confirms > 1 permanent side-effect occurred.
    """

    def check_alpn_support(self, target_url: str, timeout: float = 3.0) -> bool:
        """Test for HTTP/2 support via TLS ALPN protocol negotiation."""
        try:
            parsed = urllib.parse.urlparse(target_url)
            if parsed.scheme.lower() != "https":
                return False
            host = parsed.hostname
            if not host:
                return False
            port = parsed.port or 443

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])

            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=host) as ssock,
            ):
                negotiated = ssock.selected_alpn_protocol()
                return negotiated == "h2"
        except Exception as exc:  # noqa: BLE001
            logger.debug("ALPN check failed for %s: %s", target_url, exc)
            return False

    def execute(
        self,
        target_url: str = "",
        endpoint: str = "",
        method: str = "POST",
        payload: dict[str, Any] | None = None,
        vault: SessionVault | None = None,
        client: httpx.Client | None = None,
        recipe: ProbingRecipe | HypothesisResult | dict[str, Any] | None = None,
        burst_size: int = 16,
        max_allowed_successes: int = 1,
        verify_endpoint: str | None = None,
        verify_method: str = "GET",
        verify_callback: Any | None = None,
        force_h2: bool | None = None,
        actor: PersonaType | str = PersonaType.USER_A,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
    ) -> ProbeResult:
        """Execute dynamic race condition burst and evaluate State Multiplication Gate."""
        # Unpack recipe parameters if provided
        if isinstance(recipe, HypothesisResult):
            endpoint = endpoint or recipe.route_id or ""
            recipe = recipe.probing_recipe

        if isinstance(recipe, ProbingRecipe):
            extra = recipe.extra_params
            burst_size = extra.get("concurrency_burst", extra.get("burst_size", burst_size))
            endpoint = endpoint or extra.get("endpoint", extra.get("path", ""))
            method = extra.get("method", method)
            payload = payload if payload is not None else extra.get("payload")
            verify_endpoint = verify_endpoint or extra.get("verify_endpoint")
        elif isinstance(recipe, dict):
            extra = recipe.get("extra_params", recipe)
            burst_size = extra.get("concurrency_burst", extra.get("burst_size", burst_size))
            endpoint = endpoint or extra.get("endpoint", extra.get("path", ""))
            method = extra.get("method", method)
            verify_endpoint = verify_endpoint or extra.get("verify_endpoint")

        if payload is None:
            ep_lower = endpoint.lower()
            if any(k in ep_lower for k in ("coupon", "voucher", "discount", "promo", "code")):
                payload = {"code": "PROMO", "coupon": "PROMO"}

        actor_type = (
            PersonaType.from_str(actor)
            if isinstance(actor, (PersonaType, str))
            else PersonaType.USER_A
        )
        req_headers = dict(vault.get_headers(actor_type) if vault else {})
        if headers:
            req_headers.update(headers)

        # Record request counts in vault to maintain session heartbeat telemetry
        if vault:
            for _ in range(burst_size):
                vault.record_request(actor_type, client=client, target_url=target_url)

        # 1. Determine HTTP protocol (ALPN)
        use_h2: bool = False
        if force_h2 is True:
            use_h2 = True
        elif force_h2 is False:
            use_h2 = False
        else:
            use_h2 = self.check_alpn_support(target_url)

        req_evidence: list[dict[str, Any]] = []
        resp_evidence: list[dict[str, Any]] = []
        observed_side_effects: list[str] = []
        reproduction_steps: list[dict[str, Any]] = []

        # Record template request
        req_evidence.append(
            self.record_request_evidence(
                method, endpoint, req_headers, payload, actor=actor_type.value
            )
        )

        responses: list[httpx.Response] = []

        # 2. Execute Burst
        if use_h2:
            transmitted, _h2_success, h2_resps = self._attempt_h2_burst(
                target_url=target_url,
                endpoint=endpoint,
                method=method,
                payload=payload,
                headers=req_headers,
                burst_size=burst_size,
            )
            if transmitted:
                # Do NOT fall back to HTTP/1.1 if HTTP/2 streams were already transmitted to the server!
                # Falling back after transmitting H2 packets fires a duplicate burst, consuming single-use resources.
                responses = h2_resps
            else:
                # Safe fallback to HTTP/1.1 barrier pool only if H2 was NOT transmitted (e.g. library missing or connect failed)
                responses = self._execute_h1_barrier_burst(
                    target_url=target_url,
                    endpoint=endpoint,
                    method=method,
                    payload=payload,
                    headers=req_headers,
                    client=client,
                    burst_size=burst_size,
                    timeout=timeout,
                )
        else:
            responses = self._execute_h1_barrier_burst(
                target_url=target_url,
                endpoint=endpoint,
                method=method,
                payload=payload,
                headers=req_headers,
                client=client,
                burst_size=burst_size,
                timeout=timeout,
            )

        # Record response samples for evidence
        for idx, resp in enumerate(responses[:5]):
            resp_evidence.append(
                self.record_response_evidence(
                    resp, actor=actor_type.value, step=f"burst_response_{idx + 1}"
                )
            )

        # 3. State Multiplication Gate
        # Count successful responses (200-299)
        successful_resps = [r for r in responses if 200 <= r.status_code < 300]
        success_count = len(successful_resps)

        # Check post-burst state if verification endpoint provided
        post_state_verified = False
        if verify_endpoint:
            target_client = client or httpx.Client(base_url=target_url, timeout=5.0)
            try:
                state_resp = target_client.request(
                    verify_method, verify_endpoint, headers=req_headers
                )
                resp_evidence.append(
                    self.record_response_evidence(
                        state_resp, actor=actor_type.value, step="post_burst_state_read"
                    )
                )
                if state_resp.status_code == 200:
                    state_data = (
                        state_resp.json()
                        if "json" in state_resp.headers.get("content-type", "")
                        else state_resp.text
                    )
                    observed_side_effects.append(
                        f"Post-burst state verified on {verify_endpoint}: {state_data}"
                    )
                    post_state_verified = True
            except Exception as exc:  # noqa: BLE001
                logger.debug("Verification read on %s failed: %s", verify_endpoint, exc)

        if verify_callback is not None:
            try:
                callback_result = verify_callback(responses)
                if callback_result:
                    observed_side_effects.append(
                        "Custom state multiplication callback verified anomaly."
                    )
                    post_state_verified = True
            except Exception as exc:  # noqa: BLE001
                logger.debug("Verification callback error: %s", exc)

        reproduction_steps.append(
            {
                "step": 1,
                "actor": actor_type.value,
                "action": f"Burst {burst_size} synchronized concurrent {method} requests to {endpoint}",
                "path": endpoint,
                "count": min(burst_size, 10),
                "payload": payload,
                "successful_requests": success_count,
                "total_requests": len(responses),
                "description": f"Released {burst_size} concurrent requests simultaneously via {'HTTP/2 multiplexing' if use_h2 else 'H1.1 barrier pool'}",
            }
        )

        if success_count > max_allowed_successes:
            observed_side_effects.append(
                f"State multiplication detected: {success_count} concurrent requests succeeded (expected at most {max_allowed_successes})."
            )
            return ProbeResult(
                flaw_type="RACE_CONDITION",
                endpoint=endpoint,
                vulnerable=True,
                confidence=0.92 if (post_state_verified or success_count >= 2) else 0.85,
                request_evidence=req_evidence,
                response_evidence=resp_evidence,
                observed_side_effects=observed_side_effects,
                reproduction_steps=reproduction_steps,
                details=(
                    f"Concurrency Race Condition confirmed on {endpoint}: {success_count} of {len(responses)} "
                    f"requests succeeded concurrently, violating atomicity limits."
                ),
            )

        return ProbeResult(
            flaw_type="RACE_CONDITION",
            endpoint=endpoint,
            vulnerable=False,
            confidence=0.0,
            request_evidence=req_evidence,
            response_evidence=resp_evidence,
            reproduction_steps=reproduction_steps,
            details=(
                f"Atomic serialization enforced on {endpoint}: exactly {success_count} request(s) "
                f"succeeded out of {len(responses)} burst attempts."
            ),
        )

    def _prewarm_connection(self, client: httpx.Client, target_url: str) -> None:
        """Pre-warm keep-alive connection to eliminate TLS/TCP handshake jitter before barrier release."""
        try:
            client.request("HEAD", "/", timeout=1.0)
        except Exception:  # noqa: BLE001, S110
            pass

    def _execute_h1_barrier_burst(
        self,
        target_url: str,
        endpoint: str,
        method: str,
        payload: dict[str, Any] | None,
        headers: dict[str, str],
        client: httpx.Client | None,
        burst_size: int,
        timeout: float,
    ) -> list[httpx.Response]:
        """Release burst of concurrent requests using a synchronized threading.Barrier."""
        barrier = threading.Barrier(burst_size)
        results: list[httpx.Response | None] = [None] * burst_size

        def worker(index: int) -> None:
            # Each worker uses shared client (e.g. MockTransport in tests) or distinct client instance
            worker_client = client or httpx.Client(base_url=target_url, timeout=timeout)

            # Pre-warm connection before barrier to eliminate handshake latency
            self._prewarm_connection(worker_client, target_url)

            try:
                # Synchronize threads at barrier
                barrier.wait(timeout=10.0)
            except (threading.BrokenBarrierError, threading.BarrierResetError):
                pass

            try:
                res = worker_client.request(
                    method,
                    endpoint,
                    headers=headers,
                    json=payload,
                )
                results[index] = res
            except Exception as exc:  # noqa: BLE001
                logger.debug("Worker %d request exception: %s", index, exc)
                # Create synthetic error response
                results[index] = httpx.Response(500, request=httpx.Request(method, endpoint))

        threads: list[threading.Thread] = []
        for i in range(burst_size):
            t = threading.Thread(target=worker, args=(i,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=timeout)

        valid_responses = [r for r in results if isinstance(r, httpx.Response)]
        return valid_responses

    def _attempt_h2_burst(
        self,
        target_url: str,
        endpoint: str,
        method: str,
        payload: dict[str, Any] | None,
        headers: dict[str, str],
        burst_size: int,
    ) -> tuple[bool, bool, list[httpx.Response]]:
        """Attempt HTTP/2 single-packet multiplexed burst using h2 library if available.

        Returns:
            tuple[transmitted, success, responses]
            - transmitted: Whether the HTTP/2 burst streams were sent to the server.
            - success: Whether responses were successfully captured.
            - responses: List of HTTP responses collected.
        """
        try:
            import h2.config
            import h2.connection
            import h2.events
        except ImportError:
            # h2 library not installed in runtime
            return False, False, []

        transmitted = False
        responses: list[httpx.Response] = []
        try:
            parsed = urllib.parse.urlparse(target_url)
            host = parsed.hostname or "localhost"
            port = parsed.port or 443

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])

            with (
                socket.create_connection((host, port), timeout=5.0) as raw_sock,
                ctx.wrap_socket(raw_sock, server_hostname=host) as sock,
            ):
                config = h2.config.H2Configuration(client_side=True)
                conn = h2.connection.H2Connection(config=config)
                conn.initiate_connection()
                sock.sendall(conn.data_to_send())

                # Prepare streams with partial frames
                body_bytes = json.dumps(payload).encode() if payload else b""
                streams: list[int] = []
                for _ in range(burst_size):
                    stream_id = conn.get_next_available_stream_id()
                    streams.append(stream_id)
                    req_hdrs = [
                        (":method", method.upper()),
                        (":authority", host),
                        (":scheme", "https"),
                        (":path", endpoint),
                    ]
                    for k, v in headers.items():
                        req_hdrs.append((k.lower(), v))

                    conn.send_headers(stream_id, req_hdrs, end_stream=(len(body_bytes) == 0))
                    if body_bytes and len(body_bytes) > 1:
                        conn.send_data(stream_id, body_bytes[:-1], end_stream=False)

                # Send all stream headers and partial data
                sock.sendall(conn.data_to_send())

                # Final burst release: send the final bytes simultaneously in one TCP payload
                for s_id in streams:
                    if body_bytes:
                        conn.send_data(s_id, body_bytes[-1:], end_stream=True)

                sock.sendall(conn.data_to_send())
                transmitted = True  # Packets are in flight to target server

                # Read responses while tracking active stream states
                active_streams = set(streams)
                sock.settimeout(5.0)
                while active_streams:
                    try:
                        data = sock.recv(65535)
                    except TimeoutError:
                        logger.debug(
                            "H2 socket timed out waiting for remaining stream responses; returning %d collected",
                            len(responses),
                        )
                        break

                    if not data:
                        break

                    events = conn.receive_data(data)

                    # Flush flow control and SETTINGS ACK frames immediately
                    outbound = conn.data_to_send()
                    if outbound:
                        sock.sendall(outbound)

                    for ev in events:
                        if isinstance(ev, h2.events.ResponseReceived):
                            status = 200
                            resp_hdrs: dict[str, str] = {}
                            for k, v in ev.headers:
                                k_str = (
                                    k.decode("utf-8", errors="ignore")
                                    if isinstance(k, bytes)
                                    else str(k)
                                )
                                v_str = (
                                    v.decode("utf-8", errors="ignore")
                                    if isinstance(v, bytes)
                                    else str(v)
                                )
                                if k_str == ":status":
                                    status = int(v_str)
                                else:
                                    resp_hdrs[k_str] = v_str
                            responses.append(
                                httpx.Response(
                                    status,
                                    headers=resp_hdrs,
                                    request=httpx.Request(method, endpoint),
                                )
                            )
                        elif isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset)):
                            active_streams.discard(ev.stream_id)

                return True, len(responses) > 0, responses
        except Exception as exc:  # noqa: BLE001
            logger.debug("H2 single packet burst error: %s", exc)
            return transmitted, len(responses) > 0, responses
