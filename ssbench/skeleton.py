"""Innocuous project files that make the generated corpus look like a real repo.

None of these contain a planted secret. They exist so that history-walking
tools have realistic commits to traverse and so that path-based allowlisting
behaves the way it would on a real project.
"""

from __future__ import annotations

from typing import Dict

SKELETON: Dict[str, str] = {
    "README.md": (
        "# example-service\n\n"
        "A synthetic project used as a secret-scanner benchmark corpus.\n"
        "Every credential-shaped string in this repository is fabricated. See the\n"
        "benchmark manifest for ground truth.\n"
    ),
    ".gitignore": "__pycache__/\n*.pyc\n.env\n",
    "requirements.txt": "flask==3.0.3\nrequests==2.32.3\nboto3==1.34.0\n",
    "src/app/__init__.py": '"""example-service application package."""\n\n__version__ = "1.4.0"\n',
    "src/app/main.py": (
        '"""Entrypoint."""\n\n'
        "from src.app import config\n\n\n"
        "def create_app():\n"
        "    app = object()\n"
        "    return app\n"
    ),
    "tests/__init__.py": "",
    "tests/test_smoke.py": (
        "def test_imports():\n"
        "    import src.app  # noqa: F401\n\n"
        "    assert src.app.__version__\n"
    ),
}

# The at-HEAD version of a file whose secret lived only in history. The secret
# is gone; a config lookup stands in its place.
SCRUBBED_LEGACY = (
    '"""Legacy settings — credentials moved to the secrets manager."""\n\n'
    "import os\n\n"
    'API_KEY = os.environ["API_KEY"]\n'
    'DATABASE_URL = os.environ["DATABASE_URL"]\n'
)

SCRUBBED_HOTFIX = (
    '"""Hotfix module — temporary credentials removed in the following commit."""\n\n'
    "import os\n\n"
    'TOKEN = os.environ.get("TOKEN", "")\n'
)
