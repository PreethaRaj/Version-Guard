from agent import parse_query
from tools import match_version, is_configuration_vulnerable

def test_parse_query():
    package, version = parse_query("express 4.17.1")
    assert package == "express"
    assert version == "4.17.1"

def test_match_version_semver_range():
    assert match_version("4.17.1", {"versionStartIncluding": "4.0.0", "versionEndExcluding": "4.20.0"})
    assert not match_version("4.20.0", {"versionStartIncluding": "4.0.0", "versionEndExcluding": "4.20.0"})

def test_match_version_non_semver():
    assert match_version("1.0.0.Final", {"versionExact": "1.0.0"})
    assert match_version("v2.3", {"versionExact": "2.3.0"})

def test_nested_configuration():
    configurations = {
        "nodes": [
            {
                "operator": "OR",
                "cpeMatch": [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "4.0.0",
                        "versionEndExcluding": "4.20.0"
                    }
                ]
            }
        ]
    }
    assert is_configuration_vulnerable(configurations, "4.17.1")
    assert not is_configuration_vulnerable(configurations, "4.20.0")
