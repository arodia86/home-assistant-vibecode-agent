"""
Quick smoke-tests for the sanitizer.  Run with:
  cd privacy_proxy && python -m pytest test_sanitizer.py -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

# Patch the mapping file to a temp location so tests don't pollute /data
import tempfile, app.sanitizer as _s
_tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
_s.MAPPING_FILE = _tmp.name

from app.sanitizer import PrivacySanitizer


def make_sanitizer(**kwargs) -> PrivacySanitizer:
    return PrivacySanitizer(**kwargs)


def test_personal_name_roundtrip():
    s = make_sanitizer(personal_names=["Alice", "Bob"])
    text = "Turn on Alice's bedroom light and tell Bob it's done."
    sanitized = s.sanitize(text)
    assert "Alice" not in sanitized
    assert "Bob" not in sanitized
    restored = s.restore(sanitized)
    assert restored == text


def test_ip_redaction():
    s = make_sanitizer(redact_ips=True)
    text = '{"host": "192.168.1.42", "backup": "10.0.0.1"}'
    sanitized = s.sanitize(text)
    assert "192.168.1.42" not in sanitized
    assert "10.0.0.1" not in sanitized
    restored = s.restore(sanitized)
    assert "192.168.1.42" in restored


def test_mac_redaction():
    s = make_sanitizer(redact_macs=True)
    text = "Device MAC: aa:bb:cc:dd:ee:ff"
    sanitized = s.sanitize(text)
    assert "aa:bb:cc:dd:ee:ff" not in sanitized
    restored = s.restore(sanitized)
    assert "aa:bb:cc:dd:ee:ff" in restored


def test_email_redaction():
    s = make_sanitizer(redact_emails=True)
    text = "Contact admin@example.com for help"
    sanitized = s.sanitize(text)
    assert "admin@example.com" not in sanitized
    restored = s.restore(sanitized)
    assert "admin@example.com" in restored


def test_gps_redaction():
    s = make_sanitizer(redact_gps=True)
    text = '{"latitude": 51.50740, "longitude": -0.12779}'
    sanitized = s.sanitize(text)
    assert "51.50740" not in sanitized
    assert "-0.12779" not in sanitized


def test_dict_sanitize_restore():
    s = make_sanitizer(personal_names=["Jane"])
    data = {"name": "Jane", "state": "home", "nested": {"owner": "Jane's device"}}
    sanitized = s.sanitize(data)
    assert sanitized["name"] != "Jane"
    assert "Jane" not in sanitized["nested"]["owner"]
    restored = s.restore(sanitized)
    assert restored["name"] == "Jane"
    assert restored["nested"]["owner"] == "Jane's device"


def test_tokens_are_stable():
    s = make_sanitizer(personal_names=["Charlie"])
    t1 = s.sanitize("Hello Charlie")
    t2 = s.sanitize("Goodbye Charlie")
    # The token for Charlie should be the same in both
    token = [p for p in t1.split() if p.startswith("[NAME_")][0]
    assert token in t2


def test_ip_disabled():
    s = make_sanitizer(redact_ips=False)
    text = "host is 192.168.1.1"
    sanitized = s.sanitize(text)
    assert "192.168.1.1" in sanitized


def test_entity_names():
    s = make_sanitizer(entity_domains=["person"])
    entities = [
        {"entity_id": "person.john_doe", "attributes": {"friendly_name": "John Doe"}},
        {"entity_id": "light.kitchen", "attributes": {"friendly_name": "Kitchen Light"}},
    ]
    s.add_entity_names(entities)
    text = "John Doe is home, kitchen light is on"
    sanitized = s.sanitize(text)
    assert "John Doe" not in sanitized
    assert "kitchen" in sanitized.lower()  # light.kitchen is not a person domain


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(failed)
