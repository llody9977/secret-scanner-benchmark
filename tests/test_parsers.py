"""Parser normalisation: each scanner's output shape maps to a Finding."""

import json

from ssbench.parsers import parse
from ssbench.parsers._util import normalise_path


def test_normalise_path_variants():
    assert normalise_path("src/app/config.py") == "src/app/config.py"
    assert normalise_path("./src/app/config.py") == "src/app/config.py"
    assert normalise_path("file:///home/runner/work/x/x/bench/src/app/config.py") == "src/app/config.py"
    # a root-level file with no known anchor still loses the checkout prefix
    assert normalise_path("file:///home/runner/work/x/x/bench/Dockerfile") == "Dockerfile"
    assert normalise_path("/tmp/bench/infra/prod.tfvars") == "infra/prod.tfvars"


def test_gitleaks_parser(tmp_path):
    report = tmp_path / "gl.json"
    report.write_text(json.dumps([
        {"RuleID": "aws-access-token", "File": "bench/src/app/config.py", "StartLine": 14,
         "Secret": "SCANNER-MATCHED-SNIPPET-A", "Commit": "abc123"},
    ]))
    findings = parse("gitleaks", report, "gitleaks")
    assert len(findings) == 1
    assert findings[0].file == "src/app/config.py"
    assert findings[0].line == 14
    assert findings[0].raw_secret == "SCANNER-MATCHED-SNIPPET-A"


def test_trufflehog_parser(tmp_path):
    report = tmp_path / "th.json"
    report.write_text("\n".join([
        json.dumps({"DetectorName": "AWS", "Verified": False, "Raw": "secretbody",
                    "SourceMetadata": {"Data": {"Git": {"file": "src/app/config.py", "line": 14,
                                                        "commit": "deadbeef"}}}}),
        "",  # trufflehog emits blank lines / progress
    ]))
    findings = parse("trufflehog", report, "trufflehog")
    assert len(findings) == 1
    assert findings[0].file == "src/app/config.py"
    assert findings[0].verified is False


def test_sarif_parser_kingfisher_shape(tmp_path):
    report = tmp_path / "kf.sarif"
    report.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "kingfisher", "rules": [{"id": "stripe.1", "name": "Stripe"}]}},
            "results": [{
                "ruleId": "stripe.1",
                "message": {"text": "Stripe matched src/app/config.py"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/app/config.py"},
                        "region": {"startLine": 14, "snippet": {"text": "SCANNER-MATCHED-SNIPPET-B"}},
                    },
                    "properties": {"git_metadata": {"commit": "abcdef0"}},
                }],
            }],
        }],
    }))
    findings = parse("sarif", report, "kingfisher")
    assert len(findings) == 1
    assert findings[0].file == "src/app/config.py"
    assert findings[0].line == 14
    assert findings[0].raw_secret == "SCANNER-MATCHED-SNIPPET-B"
    assert findings[0].commit == "abcdef0"


def test_sarif_parser_titus_shape_absolute_uri(tmp_path):
    report = tmp_path / "titus.sarif"
    report.write_text(json.dumps({
        "runs": [{
            "tool": {"driver": {"name": "titus"}},
            "results": [{
                "ruleId": "np.aws.1",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "file:///home/runner/work/x/x/bench/Dockerfile"},
                        "region": {"startLine": 5, "snippet": {"text": "SCANNER-MATCHED-SNIPPET-C"}},
                    },
                }],
            }],
        }],
    }))
    findings = parse("sarif", report, "titus")
    assert len(findings) == 1
    assert findings[0].file == "Dockerfile"
    assert findings[0].line == 5


def test_detect_secrets_parser(tmp_path):
    report = tmp_path / "ds.json"
    report.write_text(json.dumps({
        "results": {
            "src/app/config.py": [
                {"type": "Secret Keyword", "line_number": 14, "hashed_secret": "a" * 40, "is_verified": False},
            ],
        },
    }))
    findings = parse("detect-secrets", report, "detect-secrets")
    assert len(findings) == 1
    assert findings[0].file == "src/app/config.py"
    assert findings[0].line == 14
    assert findings[0].raw_secret is None
