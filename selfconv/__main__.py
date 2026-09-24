"""self: the SELF swiss-army CLI."""

import argparse
import os
import shutil
import sqlite3
import struct
import sys

from .closure import build_closure
from .elf2self import convert
from .schema import APPLICATION_ID
from .self2elf import open_self

RESOLVER_SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
  id       INTEGER PRIMARY KEY,
  path     TEXT UNIQUE NOT NULL,
  soname   TEXT,
  machine  TEXT,
  build_id TEXT,
  kind     TEXT NOT NULL          -- 'self' | 'elf'
);
CREATE INDEX IF NOT EXISTS idx_objects_soname ON objects(soname, machine);
"""


def cmd_info(args) -> int:
    con = open_self(args.file)
    meta = dict(con.execute("SELECT key, value FROM self_meta"))
    for key in ("format_version", "type", "machine", "entry", "interp",
                "soname", "build_id", "source"):
        print(f"{key:16} {meta.get(key)}")
    for table in ("segments", "symbols", "relocations", "needed", "sections",
                  "notes"):
        (n,) = con.execute(f"SELECT count(*) FROM {table}").fetchone()
        print(f"{table:16} {n} rows")
    return 0


def cmd_q(args) -> int:
    con = open_self(args.file)
    for row in con.execute(args.sql):
        print("|".join("" if v is None else str(v) for v in row))
    return 0


def _sniff(path: str):
    """Return ('self'|'elf', soname, machine, build_id) or None."""
    with open(path, "rb") as f:
        head = f.read(72)
    if len(head) >= 72 and head[:16] == b"SQLite format 3\0":
        (app_id,) = struct.unpack_from(">I", head, 68)
        if app_id != APPLICATION_ID:
            return None
        con = open_self(path)
        meta = dict(con.execute("SELECT key, value FROM self_meta"))
        con.close()
        return "self", meta.get("soname"), meta.get("machine"), meta.get("build_id")
    if head[:4] == b"\x7fELF":
        import lief
        b = lief.ELF.parse(path)
        if b is None:
            return None
        soname = None
        for ent in b.dynamic_entries:
            if str(ent.tag).endswith("SONAME"):
                soname = ent.name
        from .elfimage import EM_NAMES
        em = int(b.header.machine_type)
        machine = EM_NAMES.get(em, f"em{em}")
        return "elf", soname, machine, None
    return None


def cmd_scan(args) -> int:
    con = sqlite3.connect(args.db)
    con.executescript(RESOLVER_SCHEMA)
    count = 0
    for root in args.paths:
        entries = ([root] if os.path.isfile(root) else
                   [os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs])
        for path in entries:
            try:
                info = _sniff(path)
            except Exception:
                continue
            if info is None:
                continue
            kind, soname, machine, build_id = info
            con.execute(
                "INSERT INTO objects (path, soname, machine, build_id, kind)"
                " VALUES (?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET"
                " soname=excluded.soname, machine=excluded.machine,"
                " build_id=excluded.build_id, kind=excluded.kind",
                (os.path.abspath(path), soname, machine, build_id, kind))
            count += 1
    con.commit()
    con.close()
    print(f"indexed {count} objects into {args.db}", file=sys.stderr)
    return 0


def cmd_elf2self(args) -> int:
    out = args.out or args.elf + ".self"
    convert(args.elf, out, with_sections=not args.no_sections)
    print(f"{args.elf} -> {out}", file=sys.stderr)
    return 0


def cmd_closure(args) -> int:
    if not shutil.which("ldd"):
        print("self closure: needs ldd on PATH", file=sys.stderr)
        return 1

    roots = ([args.binary] if args.binary else []) + args.root
    if args.roots_from:
        stream = sys.stdin if args.roots_from == "-" else open(args.roots_from)
        with stream:
            roots += [line.strip() for line in stream if line.strip()]
    if not roots:
        args.parser.error(
            "give a root as an argument, with --root, or via --roots-from")

    out = args.out_flag or args.out
    if out is None:
        if len(roots) > 1:
            args.parser.error("several roots need an explicit -o/--out")
        out = roots[0] + ".closure.db"

    stats = build_closure(roots, out, with_segments=not args.no_segments)
    for path in stats["skipped"]:
        print(f"self closure: skipping {path}: not an ELF file", file=sys.stderr)
    print(f"{stats['roots']} root(s) + closure -> {out} "
          f"({stats['objects']} objects, {stats['edges']} edges)",
          file=sys.stderr)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="self", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="summarize a SELF file")
    p.add_argument("file")
    p.set_defaults(fn=cmd_info)

    p = sub.add_parser("q", help="run SQL against a SELF file")
    p.add_argument("file")
    p.add_argument("sql")
    p.set_defaults(fn=cmd_q)

    p = sub.add_parser("scan", help="index objects into a resolver database")
    p.add_argument("--db", required=True)
    p.add_argument("paths", nargs="+")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("closure",
                       help="pack binaries + their closures into one DB")
    p.add_argument("binary", nargs="?", help="a root; repeat with --root")
    p.add_argument("out", nargs="?", help="default: <binary>.closure.db")
    p.add_argument("--root", action="append", default=[], metavar="PATH",
                   help="an additional root; may be given more than once")
    p.add_argument("--roots-from", metavar="FILE",
                   help="read roots from FILE, one per line ('-' for stdin)")
    p.add_argument("-o", "--out", dest="out_flag", metavar="DB",
                   help="output database; required when no positional root")
    p.add_argument("--no-segments", action="store_true",
                   help="metadata only (graph + symbols, no segment bytes)")
    p.set_defaults(fn=cmd_closure, parser=p)

    p = sub.add_parser("elf2self",
                       help="convert an ELF object into a SELF database")
    p.add_argument("elf")
    p.add_argument("out", nargs="?", help="default: <elf>.self")
    p.add_argument("--no-sections", action="store_true",
                   help="omit the optional sections table (pre-stripped)")
    p.set_defaults(fn=cmd_elf2self)

    args = ap.parse_args(sys.argv[1:] if argv is None else argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
