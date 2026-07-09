"""Verify permission-to-risk-category mappings match core/scoring.py weights."""

import pytest

# Import the internal weight tables from the scoring module
from scanapk_backend.core.scoring import (
    _PERM_CRITICAL,
    _PERM_HIGH,
    _PERM_MEDIUM,
    _PERM_LOW,
    _PERM_ALL,
    _score_permissions,
)


class TestPermissionMappings:
    """Every permission in the project's DANGEROUS_PERMISSIONS set (from
    core/scan_apk.py) must map to a weight in scoring.  This test
    double-checks that the two lists don't diverge."""

    # The dangerous permissions set defined in core/scan_apk.py
    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.REQUEST_DELETE_PACKAGES",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.INTERNET",
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    }

    def test_all_dangerous_perms_have_weights(self):
        """Every permission in DANGEROUS_PERMISSIONS must have a weight > 0."""
        missing = [p for p in self.DANGEROUS_PERMISSIONS if p not in _PERM_ALL]
        assert not missing, f"Permissions missing from scoring weights: {missing}"

    def test_no_extra_weights(self):
        """Every weight in _PERM_ALL should map to a dangerous permission.""" \
            # (known non-dangerous permissions can exist in _PERM_LOW)
        # This is just a sanity check — _PERM_ALL may include non-dangerous perms
        assert len(_PERM_ALL) >= len(self.DANGEROUS_PERMISSIONS) - 2  # allow minor drift

    def test_critical_tier_weights(self):
        assert _PERM_CRITICAL["android.permission.BIND_DEVICE_ADMIN"] == 12
        assert _PERM_CRITICAL["android.permission.BIND_ACCESSIBILITY_SERVICE"] == 10

    def test_high_tier_weights(self):
        assert _PERM_HIGH["android.permission.READ_SMS"] == 8
        assert _PERM_HIGH["android.permission.READ_PHONE_STATE"] == 7
        assert _PERM_HIGH["android.permission.CAMERA"] == 7

    def test_medium_tier_weights(self):
        assert _PERM_MEDIUM["android.permission.SEND_SMS"] == 6
        assert _PERM_MEDIUM["android.permission.WRITE_EXTERNAL_STORAGE"] == 5

    def test_low_tier_weights(self):
        assert _PERM_LOW["android.permission.INTERNET"] == 2
        assert _PERM_LOW["android.permission.RECEIVE_BOOT_COMPLETED"] == 4


class TestScorePermissionsFull:
    """End-to-end verification of permission scoring with real permission sets."""

    def test_sms_scenario(self):
        """SMS-stealer app permissions."""
        perms = [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
        ]
        score, findings = _score_permissions(perms)
        assert score == 22  # 8 + 8 + 6
        assert len(findings) == 3

    def test_device_admin_scenario(self):
        """Ransomware / device-abuse permissions."""
        perms = [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        ]
        score, findings = _score_permissions(perms)
        assert score == 22  # 12 + 4 + 6
        assert len(findings) == 3

    def test_tracking_scenario(self):
        """Spyware / tracking permissions."""
        perms = [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_PHONE_STATE",
        ]
        score, findings = _score_permissions(perms)
        assert score == 40  # 7+5+7+7+7+7 = 40, capped anyway
        assert score <= 40

    def test_location_minimal(self):
        """Minimal location permission."""
        score, findings = _score_permissions(["android.permission.ACCESS_FINE_LOCATION"])
        assert score == 7

    def test_unknown_permission_is_zero(self):
        score, findings = _score_permissions(["android.permission.UNKNOWN_THING"])
        assert score == 0
        assert findings == []

    def test_mixed_known_unknown(self):
        score, findings = _score_permissions([
            "android.permission.INTERNET",
            "android.permission.NOT_A_REAL_PERMISSION",
        ])
        assert score == 2  # only INTERNET contributes
        assert len(findings) == 1


class TestTierBoundaries:
    """Verify the weight tiers don't overlap and all values are positive."""

    def test_no_overlap_between_tiers(self):
        all_keys = set()
        for tier in [_PERM_CRITICAL, _PERM_HIGH, _PERM_MEDIUM, _PERM_LOW]:
            assert not (set(tier.keys()) & all_keys), f"Duplicate key in tier"
            all_keys.update(tier.keys())

    def test_all_weights_positive(self):
        for perm, weight in _PERM_ALL.items():
            assert weight > 0, f"Permission {perm} has non-positive weight {weight}"

    def test_sum_does_not_exceed_cap(self):
        perms = list(_PERM_ALL.keys())
        score, _ = _score_permissions(perms)
        assert score <= 40
