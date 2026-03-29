# Kept as a convenience entry point — the real CLI is aegis.cli
# Usage: python main.py <repo_url> [options]
#        or after install: aegis <repo_url> [options]

import sys
from aegis.cli import main

if __name__ == "__main__":
    sys.exit(main())
