"""Tests for the AI gateway foundation.

Written with unittest so they run with plain ``python -m unittest`` and also under pytest.
No test opens a network connection; providers are replaced by fake transports.
"""

from __future__ import annotations

import inspect
import io
import logging
import unittest

from bluestrix.ai.providers import ProviderConfig
from bluestrix.core.exceptions import ConfigurationError
from bluestrix.gateway import (
    REDACTED,
    GatewayAdapter,
    RedactingFilter,
    SecretRegistry,
    TransportError,
    TransportResponse,
    TransportTimeout,
    assess_environment,
    liveness,
    readiness,
    resolve_api_key,
    validate_base_url,
    validate_environment,
)

STRONG_JWT = "j" * 40
STRONG_MFA = "m" * 40
SAFE_DB = "postgresql+psycopg://bluestrix:Str0ng-db-pass@postgres:5432/bluestrix"
# Fake value that only matches the sk- shape so redaction can be tested. Not a real credential.
FAKE_KEY = "sk-test-0123456789abcdef0123"


def production_env(**overrides: str) -> dict[str, str]:
    env = {
        "BLUESTRIX_ENV": "production",
        "BLUESTRIX_JWT_SECRET": STRONG_JWT,
        "BLUESTRIX_MFA_KEY": STRONG_MFA,
        "DATABASE_URL": SAFE_DB,
    }
    env.update(overrides)
    return env


class FakeTransport:
    """Scripted transport. Each entry is a TransportResponse or an exception to raise."""

    def __init__(self, script):
        self.script = list(script)
        self.calls: list[dict] = []

    def post_json(self, url, *, headers, payload, timeout):
        self.calls.append({"url": url, "headers": dict(headers), "timeout": timeout})
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def ok_body(text: str = "triage ok", prompt: int = 100, completion: int = 20) -> dict:
    return {
        "choices": [{"message": {"content": text}}],
        "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
    }


def deepseek_config(base_url: str = "https://model.inferx.net/endpoints/v1") -> ProviderConfig:
    return ProviderConfig(
        name="deepseek",
        enabled=True,
        priority=1,
        base_url=base_url,
        model="deepseek-v4.1-flash-1017",
        max_tokens=1000,
        cost_per_1k_input=0.00005,
        cost_per_1k_output=0.0002,
        api_key_env="DEEPSEEK_API_KEY",
    )


class NoSleep:
    def __init__(self):
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


class SettingsValidationTests(unittest.TestCase):
    def test_development_accepts_placeholders_with_warnings(self):
        env = {"BLUESTRIX_ENV": "development", "BLUESTRIX_JWT_SECRET": "change-me"}
        report = assess_environment(env)
        self.assertTrue(report.ok)
        self.assertEqual(report.environment.value, "development")
        self.assertTrue(any("BLUESTRIX_JWT_SECRET" in w for w in report.warnings))

    def test_unset_environment_fails_secure_as_production(self):
        report = assess_environment({})
        self.assertFalse(report.ok)
        self.assertEqual(report.environment.value, "production")
        self.assertTrue(any("BLUESTRIX_ENV" in p for p in report.problems))

    def test_production_with_strong_distinct_secrets_is_accepted(self):
        settings = validate_environment(production_env())
        self.assertEqual(settings.environment.value, "production")
        self.assertEqual(settings.timeout_seconds, 30.0)
        self.assertEqual(settings.max_retries, 1)

    def test_production_rejects_missing_jwt_secret_by_name_only(self):
        env = production_env()
        del env["BLUESTRIX_JWT_SECRET"]
        report = assess_environment(env)
        self.assertFalse(report.ok)
        joined = " ".join(report.problems)
        self.assertIn("BLUESTRIX_JWT_SECRET", joined)

    def test_production_rejects_placeholder_secret(self):
        report = assess_environment(production_env(BLUESTRIX_MFA_KEY="change-me"))
        self.assertFalse(report.ok)
        self.assertTrue(any("BLUESTRIX_MFA_KEY" in p for p in report.problems))

    def test_production_rejects_short_secret(self):
        report = assess_environment(production_env(BLUESTRIX_JWT_SECRET="short-secret"))
        self.assertFalse(report.ok)
        self.assertTrue(any("at least 32" in p for p in report.problems))

    def test_production_rejects_dev_jwt_secret(self):
        report = assess_environment(production_env(BLUESTRIX_DEV_JWT_SECRET="x" * 40))
        self.assertFalse(report.ok)
        self.assertTrue(any("BLUESTRIX_DEV_JWT_SECRET" in p for p in report.problems))

    def test_production_requires_mfa_key_distinct_from_jwt(self):
        report = assess_environment(production_env(BLUESTRIX_MFA_KEY=STRONG_JWT))
        self.assertFalse(report.ok)
        self.assertTrue(any("must differ" in p for p in report.problems))

    def test_production_rejects_placeholder_database_password(self):
        report = assess_environment(
            production_env(DATABASE_URL="postgresql+psycopg://u:change-me@h:5432/db")
        )
        self.assertFalse(report.ok)
        self.assertTrue(any("DATABASE_URL" in p for p in report.problems))

    def test_forbidden_wallet_secret_env_is_rejected_in_every_environment(self):
        report = assess_environment({"BLUESTRIX_ENV": "development", "PRIVATE_KEY": "0xabc"})
        self.assertFalse(report.ok)
        self.assertTrue(any("PRIVATE_KEY" in p for p in report.problems))

    def test_mode_and_execution_must_stay_defensive_and_restricted(self):
        report = assess_environment(
            {"BLUESTRIX_ENV": "development", "BLUESTRIX_EXECUTION": "unrestricted"}
        )
        self.assertFalse(report.ok)

    def test_timeout_and_retries_are_bounded(self):
        report = assess_environment(
            {"BLUESTRIX_ENV": "development", "BLUESTRIX_AI_TIMEOUT_SECONDS": "999"}
        )
        self.assertFalse(report.ok)
        report = assess_environment(
            {"BLUESTRIX_ENV": "development", "BLUESTRIX_AI_MAX_RETRIES": "9"}
        )
        self.assertFalse(report.ok)

    def test_validate_environment_error_never_contains_secret_values(self):
        env = production_env(BLUESTRIX_DEV_JWT_SECRET=FAKE_KEY, BLUESTRIX_MFA_KEY=STRONG_JWT)
        with self.assertRaises(ConfigurationError) as ctx:
            validate_environment(env)
        message = str(ctx.exception)
        self.assertNotIn(FAKE_KEY, message)
        self.assertNotIn(STRONG_JWT, message)
        self.assertIn("BLUESTRIX_DEV_JWT_SECRET", message)

    def test_base_url_must_be_https_allowlisted_and_credential_free(self):
        self.assertEqual(
            validate_base_url("https://model.inferx.net/endpoints/v1/"),
            "https://model.inferx.net/endpoints/v1",
        )
        for bad in (
            "http://model.inferx.net/endpoints/v1",          # not https
            "https://169.254.169.254/latest/meta-data",      # metadata SSRF target
            "https://localhost:8080/x",                      # internal host
            "https://evil.example.com/v1",                   # not allowlisted
            "https://user:pw@model.inferx.net/v1",           # embedded credentials
            "https://model.inferx.net:8443/v1",              # non-default port
        ):
            with self.subTest(url=bad):
                with self.assertRaises(ConfigurationError):
                    validate_base_url(bad)

    def test_deepseek_base_url_override_is_checked(self):
        report = assess_environment(
            {"BLUESTRIX_ENV": "development", "DEEPSEEK_BASE_URL": "https://169.254.169.254/"}
        )
        self.assertFalse(report.ok)
        self.assertTrue(any("DEEPSEEK_BASE_URL" in p for p in report.problems))


class RedactionTests(unittest.TestCase):
    def test_registered_secret_value_is_removed_from_text(self):
        registry = SecretRegistry()
        registry.register(FAKE_KEY)
        out = registry.redact(f"upstream said: key={FAKE_KEY} failed")
        self.assertNotIn(FAKE_KEY, out)
        self.assertIn(REDACTED, out)

    def test_short_values_are_not_registered(self):
        registry = SecretRegistry()
        registry.register("abc")
        self.assertEqual(len(registry), 0)

    def test_bearer_sk_and_header_shapes_are_redacted(self):
        registry = SecretRegistry()
        text = (
            "Authorization: Bearer abcdef1234567890XYZ "
            f"and {FAKE_KEY} and x-api-key: supersecretvalue1"
        )
        out = registry.redact(text)
        self.assertNotIn("abcdef1234567890XYZ", out)
        self.assertNotIn(FAKE_KEY, out)
        self.assertNotIn("supersecretvalue1", out)

    def test_sensitive_headers_are_dropped_from_structured_data(self):
        data = {"headers": {"Authorization": "Bearer zzzzzzzzzzzz", "Accept": "json"}, "n": 1}
        out = SecretRegistry().redact_data(data)
        self.assertEqual(out["headers"]["Authorization"], REDACTED)
        self.assertEqual(out["headers"]["Accept"], "json")
        self.assertEqual(out["n"], 1)

    def test_logging_filter_keeps_secrets_out_of_log_output(self):
        registry = SecretRegistry()
        registry.register(FAKE_KEY)
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(RedactingFilter(registry))
        logger = logging.getLogger("bluestrix.test.redaction")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)
        try:
            logger.info("calling provider with key %s", FAKE_KEY)
            try:
                raise RuntimeError(f"boom {FAKE_KEY}")
            except RuntimeError:
                logger.exception("failed")
        finally:
            logger.handlers = []
        output = stream.getvalue()
        self.assertNotIn(FAKE_KEY, output)
        self.assertIn(REDACTED, output)

    def test_safe_error_is_short_and_redacted(self):
        registry = SecretRegistry()
        registry.register(FAKE_KEY)
        text = registry.safe_error(TransportError("bad " + FAKE_KEY + " " + "x" * 500))
        self.assertNotIn(FAKE_KEY, text)
        self.assertLess(len(text), 260)


class HealthTests(unittest.TestCase):
    def test_liveness_takes_no_arguments_and_reports_ok(self):
        self.assertEqual(liveness(), {"status": "ok"})
        self.assertEqual(list(inspect.signature(liveness).parameters), [])

    def test_readiness_has_no_transport_or_adapter_parameter(self):
        # Readiness must not be able to send a paid provider request.
        self.assertEqual(list(inspect.signature(readiness).parameters), ["env"])

    def test_readiness_ready_for_valid_production_config(self):
        ok, body = readiness(production_env(DEEPSEEK_API_KEY=FAKE_KEY))
        self.assertTrue(ok)
        self.assertEqual(body["status"], "ready")
        self.assertEqual(body["checks"]["ai_providers_configured"], 1)

    def test_readiness_not_ready_and_hides_secret_values(self):
        env = production_env(BLUESTRIX_JWT_SECRET="change-me", DEEPSEEK_API_KEY=FAKE_KEY)
        ok, body = readiness(env)
        self.assertFalse(ok)
        self.assertEqual(body["status"], "not_ready")
        rendered = repr(body)
        self.assertNotIn(FAKE_KEY, rendered)
        self.assertNotIn("BLUESTRIX_JWT_SECRET", rendered)  # problem text stays server-side


class AdapterTests(unittest.TestCase):
    def make(self, script, *, api_key=FAKE_KEY, max_retries=1, timeout=30.0, config=None):
        transport = FakeTransport(script)
        sleep = NoSleep()
        adapter = GatewayAdapter(
            config or deepseek_config(),
            transport=transport,
            api_key=api_key,
            timeout_seconds=timeout,
            max_retries=max_retries,
            sleep=sleep,
            registry=SecretRegistry(),
        )
        return adapter, transport, sleep

    def test_success_returns_text_cost_and_authorization_header(self):
        adapter, transport, _ = self.make([TransportResponse(200, ok_body("hello"))])
        result = adapter.complete([{"role": "user", "content": "scan"}])
        self.assertEqual(result.text, "hello")
        self.assertEqual(result.provider, "deepseek")
        self.assertIsNone(result.error)
        self.assertGreater(result.cost_usd, 0)
        self.assertEqual(
            transport.calls[0]["url"], "https://model.inferx.net/endpoints/v1/chat/completions"
        )
        self.assertEqual(transport.calls[0]["headers"]["Authorization"], f"Bearer {FAKE_KEY}")
        self.assertEqual(transport.calls[0]["timeout"], 30.0)

    def test_transient_503_is_retried_once_then_succeeds(self):
        adapter, transport, sleep = self.make(
            [TransportResponse(503, None), TransportResponse(200, ok_body("recovered"))]
        )
        result = adapter.complete([{"role": "user", "content": "x"}])
        self.assertEqual(result.text, "recovered")
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(len(sleep.calls), 1)

    def test_client_error_401_is_never_retried(self):
        adapter, transport, sleep = self.make([TransportResponse(401, None)], max_retries=3)
        result = adapter.complete([{"role": "user", "content": "x"}])
        self.assertEqual(result.error, "http_401")
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(sleep.calls, [])

    def test_retries_are_bounded_on_repeated_timeouts(self):
        adapter, transport, sleep = self.make(
            [TransportTimeout("slow"), TransportTimeout("slow"), TransportTimeout("slow")],
            max_retries=2,
        )
        result = adapter.complete([{"role": "user", "content": "x"}])
        self.assertEqual(result.error, "timeout")
        self.assertEqual(len(transport.calls), 3)  # 1 attempt + 2 retries, no more
        self.assertEqual(len(sleep.calls), 2)

    def test_timeout_and_transport_errors_never_leak_the_key(self):
        leaky = TransportError(f"connection to host failed while sending Bearer {FAKE_KEY}")
        adapter, _, _ = self.make([leaky, leaky], max_retries=1)
        result = adapter.complete([{"role": "user", "content": "x"}])
        self.assertNotIn(FAKE_KEY, result.error or "")
        self.assertIn(REDACTED, result.error)

    def test_missing_or_placeholder_key_fails_without_any_request(self):
        for key in (None, "", "change-me"):
            with self.subTest(key=key):
                adapter, transport, _ = self.make([], api_key=key)
                result = adapter.complete([{"role": "user", "content": "x"}])
                self.assertEqual(result.error, "missing_api_key")
                self.assertEqual(transport.calls, [])

    def test_unexpected_response_shape_is_not_retried(self):
        adapter, transport, _ = self.make([TransportResponse(200, {"oops": True})], max_retries=3)
        result = adapter.complete([{"role": "user", "content": "x"}])
        self.assertEqual(result.error, "unexpected_response")
        self.assertEqual(len(transport.calls), 1)

    def test_repr_and_error_never_contain_the_key(self):
        adapter, _, _ = self.make([TransportResponse(500, {"echo": FAKE_KEY})], max_retries=0)
        self.assertNotIn(FAKE_KEY, repr(adapter))
        result = adapter.complete([{"role": "user", "content": "x"}])
        self.assertNotIn(FAKE_KEY, repr(result))

    def test_adapter_rejects_non_allowlisted_base_url_at_construction(self):
        with self.assertRaises(ConfigurationError):
            GatewayAdapter(
                deepseek_config(base_url="https://169.254.169.254/v1"),
                transport=FakeTransport([]),
                api_key=FAKE_KEY,
            )

    def test_timeout_and_retries_are_clamped(self):
        adapter, _, _ = self.make([], timeout=9999, max_retries=50)
        self.assertEqual(adapter.timeout_seconds, 120.0)
        self.assertEqual(adapter.max_attempts, 4)  # cap of 3 retries
        adapter, _, _ = self.make([], timeout=0.001, max_retries=-5)
        self.assertEqual(adapter.timeout_seconds, 1.0)
        self.assertEqual(adapter.max_attempts, 1)

    def test_resolve_api_key_reads_mapping_and_ignores_placeholders(self):
        self.assertEqual(
            resolve_api_key({"DEEPSEEK_API_KEY": " abc123456 "}, "DEEPSEEK_API_KEY"),
            "abc123456",
        )
        self.assertIsNone(resolve_api_key({"DEEPSEEK_API_KEY": "change-me"}, "DEEPSEEK_API_KEY"))
        self.assertIsNone(resolve_api_key({}, ""))


if __name__ == "__main__":
    unittest.main()
