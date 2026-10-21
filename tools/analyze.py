"""Turn the inspector CSV into a verdict.

    python tools/analyze.py --csv traffic.csv

The report answers the two questions the whole project is about:

  * is a device talking to somewhere it should not?  (a new destination, a
    port that is not a normal service)
  * is a device sending something it should not?  (a stream that never
    stops, in the middle of the night)

Everything else - the destinations, the ports, the hour of the day - is
printed below the verdict, for when you want to look at the details.

With ``--baseline`` the file of an earlier day is the reference, so only what
is *new* is reported:

    python tools/analyze.py --csv traffic.csv --baseline yesterday.csv

The work is done in ``server/report.py``, the same module the server uses
when a phone asks for the report over the tunnel.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.report import *  # noqa: F401,F403
from server.report import (  # noqa: F401
    ReportError,
    collect_findings,
    find_baseline,
    load,
    load_baseline,
    make_report,
    parse_args,
    reports_folder,
    report_text,
    save_report,
    verdict,
)


def main(argv=None):
    options = parse_args(argv)
    try:
        rows = load(options.csv)
    except ReportError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    baseline = load_baseline(options)
    findings = collect_findings(rows, baseline, options)
    text = report_text(rows, findings, options)
    print(text)
    if not options.no_save:
        path = save_report(text, options.csv, options.reports_dir)
        if path:
            print("[*] the report is also in %s" % path)
    # something to look at?  the exit code says so, handy for a cron job
    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
