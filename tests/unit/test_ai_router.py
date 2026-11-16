from bluestrix.ai.providers import CompletionResult, ProviderConfig
from bluestrix.ai.router import AIRouter, load_router_config
from bluestrix.integrations.deepseek import deepseek_config


class FakeProvider:
    def __init__(self, name: str, fail: bool = False, text: str = "ok"):
        self.name = name
        self.fail = fail
        self.text = text
        self.calls = 0

    def complete(self, messages, **kwargs):
        self.calls += 1
        if self.fail:
            return CompletionResult(text="", provider=self.name, model="m", error="fail")
        return CompletionResult(text=self.text, provider=self.name, model="m", cost_usd=0.001)


def test_deepseek_config_priority():
    cfg = deepseek_config()
    assert cfg.name == "deepseek"
    assert cfg.priority == 1
    assert "inferx.net" in cfg.base_url
    assert cfg.model == "deepseek-v4.1-flash-1017"


def test_default_order_deepseek_first():
    data = load_router_config()
    names = [p["name"] for p in data["providers"] if p.get("enabled")]
    assert names[0] == "deepseek"
    assert "openai" in names and "anthropic" in names and "groq" in names and "local" in names


def test_deepseek_selected_as_priority_1():
    deepseek = FakeProvider("deepseek", text="from-deepseek")
    openai = FakeProvider("openai", text="from-openai")
    router = AIRouter(providers=[deepseek, openai, FakeProvider("local")])
    result = router.complete([{"role": "user", "content": "hi"}], use_cache=False)
    assert result.provider == "deepseek"
    assert result.text == "from-deepseek"
    assert openai.calls == 0


def test_fallback_openai_when_deepseek_fails():
    deepseek = FakeProvider("deepseek", fail=True)
    openai = FakeProvider("openai", text="from-openai")
    router = AIRouter(providers=[deepseek, openai, FakeProvider("local")])
    result = router.complete([{"role": "user", "content": "hi"}], use_cache=False)
    assert result.provider == "openai"


def test_fallback_anthropic_when_openai_fails():
    router = AIRouter(
        providers=[
            FakeProvider("deepseek", fail=True),
            FakeProvider("openai", fail=True),
            FakeProvider("anthropic", text="from-anthropic"),
            FakeProvider("local"),
        ]
    )
    result = router.complete([{"role": "user", "content": "hi"}], use_cache=False)
    assert result.provider == "anthropic"


def test_fallback_groq_when_anthropic_fails():
    router = AIRouter(
        providers=[
            FakeProvider("deepseek", fail=True),
            FakeProvider("openai", fail=True),
            FakeProvider("anthropic", fail=True),
            FakeProvider("groq", text="from-groq"),
            FakeProvider("local"),
        ]
    )
    result = router.complete([{"role": "user", "content": "hi"}], use_cache=False)
    assert result.provider == "groq"


def test_fallback_local_when_all_fail():
    router = AIRouter(
        providers=[
            FakeProvider("deepseek", fail=True),
            FakeProvider("openai", fail=True),
            FakeProvider("anthropic", fail=True),
            FakeProvider("groq", fail=True),
            FakeProvider("local", text="from-local"),
        ]
    )
    result = router.complete([{"role": "user", "content": "hi"}], use_cache=False)
    assert result.provider == "local"
    assert "from-local" in result.text


def test_cache_and_quota():
    p = FakeProvider("deepseek", text="cached-me")
    router = AIRouter(
        config={"budget_usd_daily": 5.0, "cache_ttl_seconds": 3600, "cooldown_seconds": 30},
        providers=[p],
    )
    messages = [{"role": "user", "content": "same"}]
    r1 = router.complete(messages, use_cache=True)
    r2 = router.complete(messages, use_cache=True)
    assert p.calls == 1
    assert r2.cached is True
    snap = router.quota_snapshot()
    assert snap["calls"] == 1
    assert snap["spend_usd"] >= 0
