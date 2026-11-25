"""Magic-link primitives.

A link token is represented as a dictionary.  The store is a mutable mapping
that owns the issued token records and the set of token identifiers that have
already been spent.

Security properties enforced here:

* identifiers are generated with a cryptographically secure random source, so
  they cannot be predicted or enumerated;
* every token is bound to the exact device and subject that requested it;
* tokens have a short, enforced lifetime;
* a token can be spent exactly once, and only by the matching device/subject;
* a failed presentation (wrong binding or stale token) never spends a token;
* batch validation resolves each entry by its own identifier and never lets
  one entry affect another.
"""

import hashlib
import hmac
import secrets

MIN_ENTROPY_BITS = 128
MAX_TTL_SECONDS = 900
MIN_TOKEN_ID_LENGTH = 16
DEFAULT_TTL_SECONDS = 300

# token_urlsafe(32) carries 256 bits of entropy and yields 43 URL-safe chars.
_TOKEN_BYTES = 32


def _token_id(token):
    """Return the identifier carried by a token reference."""
    if isinstance(token, dict):
        return token.get("id")
    return token


def _entropy_bits_for(entropy, policy):
    """Return the entropy advertised by the token.

    The identifier is always generated with 256 random bits, so the advertised
    value is at least the platform minimum and never below what the caller
    asked for.
    """
    try:
        requested = int(entropy)
    except (TypeError, ValueError):
        requested = 0
    floor = MIN_ENTROPY_BITS
    policy_floor = policy.get("min_entropy_bits")
    if isinstance(policy_floor, (int, float)):
        floor = max(floor, int(policy_floor))
    return max(requested, floor)


def _ttl_seconds_for(policy):
    """Return a safe, short lifetime for a new token."""
    try:
        ttl = int(policy.get("ttl_seconds", DEFAULT_TTL_SECONDS))
    except (TypeError, ValueError):
        ttl = DEFAULT_TTL_SECONDS
    if ttl <= 0:
        ttl = DEFAULT_TTL_SECONDS
    return min(ttl, MAX_TTL_SECONDS)


def issue(store, subject, device, entropy, now, policy):
    """Issue a fresh magic-link token and return it."""
    tokens = store.setdefault("tokens", {})
    store.setdefault("used", set())

    policy = dict(policy or {})
    ttl = _ttl_seconds_for(policy)
    entropy_bits = _entropy_bits_for(entropy, policy)

    # A CSPRNG identifier is unguessable and unique; never a counter.
    token_id = secrets.token_urlsafe(_TOKEN_BYTES)

    binding = bind_hash({"id": token_id}, device, subject)
    token = {
        "id": token_id,
        "issued_at": now,
        "ttl_seconds": ttl,
        "expires_at": now + ttl,
        "entropy_bits": entropy_bits,
        "device": device,
        "subject": subject,
        "binding": binding,
    }
    tokens[token_id] = dict(token)
    return dict(token)


def bind_hash(token, device, subject):
    """Return the digest that ties a token to a device and a subject."""
    token_id = token.get("id", "") if isinstance(token, dict) else str(token)
    material = "%s|%s|%s" % (token_id, device, subject)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def check_binding(token, device, subject):
    """Return whether the presented device and subject match the token."""
    if not isinstance(token, dict):
        return False
    expected = bind_hash(token, device, subject)
    actual = token.get("binding")
    if not isinstance(actual, str):
        return False
    # Both device and subject must be present for a binding to count.
    if not isinstance(device, str) or not device:
        return False
    if not isinstance(subject, str) or not subject:
        return False
    return hmac.compare_digest(actual, expected)


def _valid_window(record, now, policy):
    """Return whether ``now`` falls inside the token's validity window."""
    issued = record.get("issued_at")
    ttl = record.get("ttl_seconds")
    if not isinstance(issued, (int, float)) or not isinstance(ttl, (int, float)):
        return False
    if not isinstance(now, (int, float)):
        return False
    if ttl <= 0 or ttl > MAX_TTL_SECONDS:
        return False
    # A policy may only shorten a lifetime, never extend it.
    policy_ttl = (policy or {}).get("ttl_seconds")
    if isinstance(policy_ttl, (int, float)) and 0 < policy_ttl < ttl:
        ttl = policy_ttl
    if now < issued:
        return False
    return (now - issued) <= ttl


def check_freshness(token, now, policy):
    """Return whether the token is still inside its validity window."""
    if not isinstance(token, dict):
        return False
    return _valid_window(token, now, policy)


def consume(store, token, device, subject, now):
    """Check binding and freshness, then spend the token exactly once.

    The presented token is only a reference: all decisions are made from the
    stored record, so tampering with the presented dictionary has no effect.
    A rejected presentation (already used, wrong binding, or expired) never
    spends the stored token.
    """
    token_id = _token_id(token)
    record = (store.get("tokens") or {}).get(token_id)
    if record is None:
        return {"ok": False, "reason": "unknown_token", "id": token_id}

    if is_used(store, record):
        return {"ok": False, "reason": "already_used", "id": token_id}

    if not check_binding(record, device, subject):
        return {"ok": False, "reason": "binding_mismatch", "id": token_id}

    if not _valid_window(record, now, {}):
        return {"ok": False, "reason": "expired", "id": token_id}

    # Only a fully valid presentation spends the token.
    store.setdefault("used", set()).add(token_id)
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
    elif len(token_id) < MIN_TOKEN_ID_LENGTH:
        issues.append("token id too short")

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
    """Resolve the stored record for one batch entry by its own id."""
    token_id = _token_id(token)
    if not isinstance(token_id, str) or not token_id:
        return None
    return (store.get("tokens") or {}).get(token_id)


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
        if is_used(store, record):
            reason = "already_used"
        elif not check_binding(record, device, subject):
            reason = "binding_mismatch"
        elif not _valid_window(record, now, {}):
            reason = "expired"
        else:
            reason = ""

        results.append(
            {
                "ok": reason == "",
                "id": token_id,
                "subject": record.get("subject") if reason == "" else None,
                "reason": reason,
            }
        )

    return {
        "results": results,
        "total": len(results),
        "ok_count": sum(1 for item in results if item["ok"]),
    }
