"""Entry point of the traffic-inspector tunnel server.

    python listeningServer.py --port 5555 --csv traffic.csv

The real implementation lives in the ``server`` package.
"""

import sys

from server.server import main

if __name__ == "__main__":
    sys.exit(main())
