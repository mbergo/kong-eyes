"""koe: see what the guardrail on a Kong route is doing. (Kong Eyes; "koe" is also a Brazilian hello.)

  koe connect    --route NAME --ingest-url URL [--guardrail NAME] [--timeout-ms N] [--yes]
  koe disconnect --route NAME [--yes]
  koe status
  koe demo traffic --kong-url URL --apikey KEY [--rps 60] [--minutes 10]

Kong's Admin API address comes from --admin-url or KONG_ADMIN_URL; its token, if it needs one, from
--admin-token or KONG_ADMIN_TOKEN. The collector token comes from --ingest-token or KONG_EYES_INGEST_TOKEN.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__, connect as C, demo as D


def _kong(a) -> C.Kong:
    if not a.admin_url:
        raise SystemExit("where is Kong's Admin API? Pass --admin-url or set KONG_ADMIN_URL (for example http://localhost:8001)")
    return C.Kong(a.admin_url, a.admin_token)


def _confirm(a, question: str) -> bool:
    if a.yes:
        return True
    if not sys.stdin.isatty():
        raise SystemExit("not a terminal: add --yes to apply, or --dry-run to only look")
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")


def cmd_connect(a) -> int:
    kong = _kong(a)
    p = C.plan(kong, a)
    i = p["info"]
    print(f"Kong {i['version']} ({i['edition']}, {'DB-less' if i['dbless'] else 'database'}), route {p['route'].get('name') or p['route']['id']}")
    print(f"  plugins on the route   {', '.join(p['others_on_route']) or 'none'}")
    print(f"  guardrail              {p['guardrail']}" + ("" if a.guardrail else "   (guessed: the only plugin that is not a known Kong plugin)"))
    print(f"  stops are attributed   to {p['auth'] or 'no auth plugin'} when no consumer was authenticated"
          + (f", to {p['rate']} on 429" if p["rate"] else "") + f", otherwise to {p['guardrail']}")
    print(f"  fail-open check        {'allowed after about ' + str(a.timeout_ms) + ' ms' if a.timeout_ms else 'off (pass --timeout-ms with the guardrail timeout)'}")
    print(f"  prompts                {'first ' + str(a.show_prompts) + ' bytes of each body leave Kong' if a.show_prompts else 'not captured'}")
    print(f"  will add               {', '.join(x['name'] for x in p['plugins'])}   (tagged kong-eyes; {'updating' if p['already'] else 'new'})")
    if a.print_yaml:
        print("\n# add this to your declarative config to keep it across restarts\n" + C.snippet(p))
    if a.dry_run:
        print("dry run: nothing changed")
        return 0
    if not _confirm(a, "Add these three plugins to the route?"):
        print("nothing changed")
        return 1
    C.apply(kong, p)
    print("connected." + (" This Kong is DB-less: the change lives in memory until Kong restarts; --print-yaml shows what to add to its config file."
                          if i["dbless"] else ""))
    return 0


def cmd_disconnect(a) -> int:
    kong = _kong(a)
    if not a.dry_run and not _confirm(a, f"Remove Kong Eyes from route {a.route}?"):
        print("nothing changed")
        return 1
    if a.dry_run:
        mine = [r for r in C.connected(kong) if r["route"] == a.route]
        print(f"dry run: would remove {', '.join(mine[0]['plugins']) if mine else 'nothing'}")
        return 0
    gone = C.remove(kong, a.route)
    print(f"removed {', '.join(gone)}" if gone else f"Kong Eyes was not on route {a.route}")
    return 0


def cmd_status(a) -> int:
    rows = C.connected(_kong(a))
    if not rows:
        print("Kong Eyes is not connected to any route on this Kong")
        return 0
    for r in rows:
        print(f"{r['route']:<32} -> {r['collector']}   ({', '.join(sorted(r['plugins']))})")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="koe", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--admin-url", default=os.environ.get("KONG_ADMIN_URL"))
        p.add_argument("--admin-token", default=os.environ.get("KONG_ADMIN_TOKEN"))
        p.add_argument("--yes", "-y", action="store_true", help="do not ask before changing the gateway")
        p.add_argument("--dry-run", action="store_true", help="look and report, change nothing")

    c = sub.add_parser("connect", help="start watching one route, using only plugins Kong already ships")
    common(c)
    c.add_argument("--route", required=True, help="route name or id")
    c.add_argument("--ingest-url", default=os.environ.get("KONG_EYES_INGEST_URL"), required=not os.environ.get("KONG_EYES_INGEST_URL"),
                   help="the collector, as Kong reaches it, e.g. https://eyes.example.com/ingest/kong")
    c.add_argument("--ingest-token", default=os.environ.get("KONG_EYES_INGEST_TOKEN"))
    c.add_argument("--guardrail", help="the guardrail plugin's name (guessed when exactly one unknown plugin is on the route)")
    c.add_argument("--guardrail-priority", type=int, help="its PRIORITY, only used to draw the chain in order")
    c.add_argument("--timeout-ms", type=int, help="the guardrail's timeout; enables the fail-open check")
    c.add_argument("--show-prompts", type=int, default=0, metavar="BYTES", help="also send the first BYTES of each request body (off by default)")
    c.add_argument("--no-detect-rewrites", dest="detect_rewrites", action="store_false", help="do not read the body to see whether it changed")
    c.add_argument("--environment", default="prod")
    c.add_argument("--policy-version", default=None)
    c.add_argument("--print-yaml", action="store_true", help="also print the plugins as declarative YAML")
    c.set_defaults(fn=cmd_connect)

    d = sub.add_parser("disconnect", help="remove Kong Eyes from one route")
    common(d)
    d.add_argument("--route", required=True)
    d.set_defaults(fn=cmd_disconnect)

    s = sub.add_parser("status", help="which routes are being watched")
    common(s)
    s.set_defaults(fn=cmd_status)

    dm = sub.add_parser("demo", help="drive the demo stack").add_subparsers(dest="demo_cmd", required=True)
    t = dm.add_parser("traffic", help="send a lot of synthetic requests through Kong, fast, with a mix that keeps changing",
                      description=D.__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    t.add_argument("--kong-url", default=os.environ.get("KONG_PROXY_URL", "http://localhost:8000"), help="Kong's proxy address")
    t.add_argument("--path", default="/ai/named", help="the demo route")
    t.add_argument("--apikey", default=os.environ.get("KOE_APIKEY"), required=not os.environ.get("KOE_APIKEY"))
    t.add_argument("--attacker-apikey", default="untrusted-client-key", help="a second caller, used for the attacks")
    t.add_argument("--rps", type=float, default=60)
    t.add_argument("--minutes", type=float, default=10)
    t.add_argument("--calm", action="store_true", help="one steady mix instead of the storm")
    t.add_argument("--model", default="mock-gpt")
    t.add_argument("--workers", type=int, default=48)
    t.add_argument("--report-s", type=float, default=5)
    t.set_defaults(fn=D.traffic)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
