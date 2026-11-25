from engine.magic.link import (
    check_binding,
    check_freshness,
    consume,
    issue,
    link_batch,
    validate_token,
)

POLICY = {"ttl_seconds": 300, "min_entropy_bits": 128}


def test_issue_link_binds_device_and_subject():
    store = {}
    token = issue(store, "alice", "laptop", 256, 1000, POLICY)

    assert token.get("device") == "laptop"
    assert token.get("subject") == "alice"
    assert len(token.get("id", "")) >= 16
    assert validate_token(token) == []


def test_binding_check_rejects_other_device():
    store = {}
    token = issue(store, "alice", "laptop", 256, 1000, POLICY)

    assert check_binding(token, "laptop", "alice") is True
    assert check_binding(token, "phone", "alice") is False


def test_consume_is_single_use():
    store = {}
    token = issue(store, "alice", "laptop", 256, 1000, POLICY)

    first = consume(store, token, "laptop", "alice", 1000)
    second = consume(store, token, "laptop", "alice", 1000)

    assert first["ok"] is True
    assert second["ok"] is False


def test_expired_link_is_not_fresh():
    store = {}
    token = issue(store, "alice", "laptop", 256, 1000, POLICY)

    assert check_freshness(token, 1030, POLICY) is True
    assert check_freshness(token, 1301, POLICY) is False


def test_batch_keeps_links_independent():
    store = {}
    first = issue(store, "alice", "laptop", 256, 1000, POLICY)
    second = issue(store, "bob", "phone", 256, 1000, POLICY)

    payload = link_batch(
        [
            {"token": first, "device": "laptop", "subject": "alice"},
            {"token": second, "device": "phone", "subject": "bob"},
        ],
        store,
        1000,
    )

    assert payload["ok_count"] == 2
    assert [item["id"] for item in payload["results"]] == [
        first["id"],
        second["id"],
    ]