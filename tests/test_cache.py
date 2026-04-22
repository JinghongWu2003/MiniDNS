from minidns.cache import TTLCache


def test_ttl_cache_store_and_expire(monkeypatch):
    now = 1000.0
    monkeypatch.setattr("minidns.cache.time.time", lambda: now)

    cache = TTLCache[str]()
    cache.put("Example.COM.", "a", "cached-value", ttl=2)

    assert cache.get("example.com", "A") == "cached-value"

    now = 1001.5
    assert cache.get("example.com.", "A") == "cached-value"

    now = 1002.1
    assert cache.get("example.com", "A") is None


def test_ttl_cache_stats(monkeypatch):
    now = 2000.0
    monkeypatch.setattr("minidns.cache.time.time", lambda: now)

    cache = TTLCache[str]()
    cache.put("example.com", "A", "value", ttl=10)

    cache.get("example.com", "A")
    cache.get("missing.example", "A")

    stats = cache.stats()
    assert stats["entries"] == 1
    assert stats["hits"] == 1
    assert stats["misses"] == 1
