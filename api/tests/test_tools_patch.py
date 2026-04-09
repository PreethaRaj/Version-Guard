import pytest
from tools import InvalidSoftwareVersionError, match_version, parse_version, is_configuration_vulnerable

def test_openssl_301_should_match_range():
    cfg = [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", "versionStartIncluding": "3.0.0", "versionEndExcluding": "3.0.7"}]}]}]
    assert is_configuration_vulnerable(cfg, "3.0.1", "openssl") is True

def test_openssl_307_should_not_match():
    cfg = [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", "versionStartIncluding": "3.0.0", "versionEndExcluding": "3.0.7"}]}]}]
    assert is_configuration_vulnerable(cfg, "3.0.7", "openssl") is False

def test_invalid_version_raises():
    with pytest.raises(InvalidSoftwareVersionError):
        parse_version("abc??")

def test_strict_mode_no_bounds_returns_false():
    assert match_version("1.2.3", {}, strict_mode=True) is False
