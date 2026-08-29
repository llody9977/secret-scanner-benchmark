"""Fixed values that keep the corpus reproducible.

Nothing here may be derived from wall-clock time, the host, or the environment.
Commit timestamps, author identity and the corpus "creation" date are all
pinned so that two runs of the generator from the same seed produce identical
git object hashes.
"""

from __future__ import annotations

# Pinned identity for every commit in the generated corpus repository.
GIT_AUTHOR_NAME = "ssbench corpus generator"
GIT_AUTHOR_EMAIL = "corpus@benchmark.invalid"

# Pinned base timestamp. Each commit uses CORPUS_EPOCH + (index * COMMIT_STRIDE).
CORPUS_EPOCH = 1_735_689_600  # 2025-01-01T00:00:00Z, as a Unix timestamp
COMMIT_STRIDE_SECONDS = 3_600
CORPUS_TZ = "+0000"

# Recorded verbatim in the manifest so a stale corpus is obvious.
CORPUS_CREATED = "2025-01-01T00:00:00Z"

DEFAULT_SEED = 20260829
DEFAULT_BRANCH = "main"

# The AWS account id embedded in every synthetic AWS access key id. All zeros is
# not a real account and decodes back to 0, which is the clearest possible
# signal that the key is fabricated.
SYNTHETIC_AWS_ACCOUNT_ID = 0

# Placement -> the scan capability a tool must have to see a secret in that
# placement at all. A tool lacking the capability is scored N/A for that
# placement, never as a miss.
PLACEMENT_REQUIRES = {
    "working-tree": "working-tree",
    "dotenv": "working-tree",
    "json-fixture": "working-tree",
    "jupyter-output": "working-tree",
    "dockerfile-env": "working-tree",
    "terraform-vars": "working-tree",
    "ci-log-artifact": "working-tree",
    "minified-bundle": "working-tree",
    "base64-blob": "working-tree",
    "history-depth": "history",
    "reverted-commit": "history",
    "non-default-branch": "history",
}

CAPABILITIES = ("working-tree", "history", "verification")
