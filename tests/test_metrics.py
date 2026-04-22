from minidns.metrics import Metrics


def test_metrics_summary_contains_key_fields():
    metrics = Metrics()
    metrics.record_query(
        latency_ms=12.5,
        cache_result="miss",
        upstream_queries=3,
        timeout_count=1,
        nxdomain=True,
    )
    metrics.record_query(
        latency_ms=1.2,
        cache_result="hit",
        blocked=True,
    )

    summary_text = metrics.summary_text()

    assert "total_client_queries: 2" in summary_text
    assert "cache_hits: 1" in summary_text
    assert "cache_misses: 1" in summary_text
    assert "blocked_queries: 1" in summary_text
    assert "upstream_queries: 3" in summary_text
    assert "upstream_timeouts: 1" in summary_text
    assert "nxdomain_count: 1" in summary_text
