import time

from backend.services import cookieHttpOnly, cookieSecure, responseCode

PER_TARGET_DELAY = 0.25
TARGET_COUNT = 8
SERIAL_TOTAL = PER_TARGET_DELAY * TARGET_COUNT


def run_with_elapsed(func, targets):
    start = time.monotonic()
    results = func(targets)
    elapsed = time.monotonic() - start
    return elapsed, results


def test_run_cookie_scan_is_parallel_and_ordered(monkeypatch):
    def fake_check(target):
        time.sleep(PER_TARGET_DELAY)
        return {"url": target, "status": "SAFE", "message": "ok"}

    monkeypatch.setattr(cookieSecure, "check_cookie_security", fake_check)

    targets = [f"https://target-{index}.example.com" for index in range(TARGET_COUNT)]
    elapsed, results = run_with_elapsed(cookieSecure.run_cookie_scan, targets)

    assert [item["url"] for item in results] == targets
    assert elapsed < SERIAL_TOTAL / 2


def test_run_cookie_scan_skips_blank_targets(monkeypatch):
    def fake_check(target):
        return {"url": target, "status": "SAFE", "message": "ok"}

    monkeypatch.setattr(cookieSecure, "check_cookie_security", fake_check)

    results = cookieSecure.run_cookie_scan(["", "   ", "https://real.example.com"])

    assert [item["url"] for item in results] == ["https://real.example.com"]


def test_run_cookie_httponly_scan_is_parallel_and_ordered(monkeypatch):
    def fake_check(target):
        time.sleep(PER_TARGET_DELAY)
        return {"url": target, "status": "SAFE", "message": "ok"}

    monkeypatch.setattr(cookieHttpOnly, "check_cookie_httponly", fake_check)

    targets = [f"https://target-{index}.example.com" for index in range(TARGET_COUNT)]
    elapsed, results = run_with_elapsed(cookieHttpOnly.run_cookie_httponly_scan, targets)

    assert [item["url"] for item in results] == targets
    assert elapsed < SERIAL_TOTAL / 2


def test_run_response_code_scan_is_parallel_and_ordered(monkeypatch):
    def fake_check(target):
        time.sleep(PER_TARGET_DELAY)
        return {"URL": target, "Status Code": 200, "Category": "SUCCESS"}

    monkeypatch.setattr(responseCode, "check_response_code", fake_check)

    targets = [f"https://target-{index}.example.com" for index in range(TARGET_COUNT)]
    elapsed, results = run_with_elapsed(responseCode.run_response_code_scan, targets)

    assert [item["URL"] for item in results] == targets
    assert elapsed < SERIAL_TOTAL / 2
