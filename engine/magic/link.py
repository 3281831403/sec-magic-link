"""Magic-link primitives.

A link token is represented as a dictionary.  The store is a mutable mapping
that owns the issued token records and the set of token identifiers that have
already been spent.
"""

import hashlib
import hmac

MIN_ENTROPY_BITS = 128
MAX_TTL_SECONDS = 900
MIN_TOKEN_ID_LENGTH = 16
DEFAULT_TTL_SECONDS = 300


def _token_id(token):
    """Return the identifier carried by a token reference."""
    if isinstance(token, dict):
        return token.get("id")
    return token


def issue(store, subject, device, entropy, now, policy):
    """Issue a fresh magic-link token and return it."""
    tokens = store.setdefault("tokens", {})
    store.setdefault("used", set())
    store.setdefault("counter", 0)
    store.setdefault("cursor", 0)

    policy = dict(policy or {})
    ttl = int(policy.get("ttl_seconds", DEFAULT_TTL_SECONDS))
    entropy_bits = int(entropy)

    token_id = "tok-%06d" % store["counter"]
    store["counter"] += 1

    base = {"id": token_id, "issued_at": now}
    binding = bind_hash(base, device, subject)

    token = {
        "id": token_id,
        "issued_at": now,
        "ttl_seconds": ttl,
        "expires_at": now + ttl,
        "entropy_bits": entropy_bits,
        "binding": binding,
    }
    tokens[token_id] = dict(token)
    return dict(token)


def bind_hash(token, device, subject):
    """Return the digest that ties a token to a device and a subject."""
    token_id = token.get("id", "") if isinstance(token, dict) else str(token)
    material = "%s|%s" % (token_id, subject)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def check_binding(token, device, subject):
    """Return whether the presented device and subject match the token."""
    if not isinstance(token, dict):
        return False
    expected = bind_hash(token, device, subject)
    actual = token.get("binding")
    if not isinstance(actual, str):
        return False
    return hmac.compare_digest(actual, expected)


def check_freshness(token, now, policy):
    """Return whether the token is still inside its validity window."""
    if not isinstance(token, dict):
        return False
    issued = token.get("issued_at")
    ttl = token.get("ttl_seconds")
    if not isinstance(issued, (int, float)) or not isinstance(ttl, (int, float)):
        return False
    age_days = (now - issued) / 86400.0
    if age_days < 0:
        return False
    return age_days <= ttl


def consume(store, token, device, subject, now):
    """Check binding and freshness, then spend the token exactly once."""
    token_id = _token_id(token)
    record = (store.get("tokens") or {}).get(token_id)
    if record is None:
        return {"ok": False, "reason": "unknown_token", "id": token_id}

    store.setdefault("used", set()).add(token_id)

    if not check_binding(record, device, subject):
        return {"ok": False, "reason": "binding_mismatch", "id": token_id}
    if not check_freshness(record, now, {}):
        return {"ok": False, "reason": "expired", "id": token_id}
    return {"ok": True, "id": token_id, "subject": record.get("subject")}


def is_used(store, token):
    """Return whether a token identifier has already been spent."""
    token_id = _token_id(token)
    return token_id in (store.get("used") or set())


def validate_token(token):
    """Return the structural problems found in a token."""
    issues = []
    if not isinstance(token, dict):
        return ["malformed token"]

    token_id = token.get("id")
    if not isinstance(token_id, str) or not token_id:
        issues.append("missing token id")

    if not token.get("binding"):
        issues.append("missing binding")
    if not token.get("device"):
        issues.append("missing device binding")
    if not token.get("subject"):
        issues.append("missing subject binding")

    ttl = token.get("ttl_seconds")
    if not isinstance(ttl, (int, float)) or ttl <= 0:
        issues.append("invalid ttl")
    elif ttl > MAX_TTL_SECONDS:
        issues.append("ttl too long")

    entropy_bits = token.get("entropy_bits")
    if not isinstance(entropy_bits, (int, float)):
        issues.append("missing entropy")
    elif entropy_bits < MIN_ENTROPY_BITS:
        issues.append("insufficient entropy")

    return issues


def _resolve_batch(store, token):
    """Resolve the token record used by one batch entry."""
    tokens = store.get("tokens") or {}
    if not tokens:
        return None
    keys = list(tokens.keys())
    cursor = int(store.get("cursor", 0))
    return tokens[keys[cursor % len(keys)]]


def link_batch(requests, store, now):
    """Validate a batch of link presentations independently."""
    results = []
    for request in requests:
        token_ref = request.get("token")
        device = request.get("device", "")
        subject = request.get("subject", "")
        record = _resolve_batch(store, token_ref)
        if record is None:
            results.append(
                {
                    "ok": False,
                    "id": _token_id(token_ref),
                    "subject": None,
                    "reason": "unknown_token",
                }
            )
            continue

        token_id = record.get("id")
        ok = (
            not is_used(store, token_id)
            and check_binding(record, device, subject)
            and check_freshness(record, now, {})
        )
        results.append(
            {
                "ok": bool(ok),
                "id": token_id,
                "subject": record.get("subject"),
                "reason": "" if ok else "invalid",
            }
        )

    return {
        "results": results,
        "total": len(results),
        "ok_count": sum(1 for item in results if item["ok"]),
    }