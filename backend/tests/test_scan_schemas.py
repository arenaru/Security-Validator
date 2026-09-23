import pytest

from backend.models.scan_models import MAX_TARGETS_PER_SCAN
from backend.schemas.scan_schemas import ScanCreateRequest


def make_request(target_count, modules=None):
    return ScanCreateRequest(
        targets=[f"https://target-{index}.example.com" for index in range(target_count)],
        modules=modules or ["SSL Certificate Check"],
    )


def test_validate_rejects_too_many_targets():
    request = make_request(MAX_TARGETS_PER_SCAN + 1)

    with pytest.raises(ValueError, match="targets must not exceed"):
        request.validate()


def test_validate_accepts_target_cap():
    request = make_request(MAX_TARGETS_PER_SCAN)

    request.validate()


def test_validate_rejects_empty_targets():
    request = ScanCreateRequest(targets=[], modules=["SSL Certificate Check"])

    with pytest.raises(ValueError, match="targets must not be empty"):
        request.validate()


def test_validate_rejects_unknown_module():
    request = ScanCreateRequest(targets=["example.com"], modules=["Not A Real Module"])

    with pytest.raises(ValueError, match="unknown modules"):
        request.validate()
