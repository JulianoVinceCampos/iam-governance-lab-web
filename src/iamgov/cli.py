"""Entrypoint de linha de comando: validate, scan, report e serve.

    iamgov validate --data data
    iamgov scan     --data data
    iamgov report   --data data --out out
    iamgov serve    --data data --host 127.0.0.1 --port 8000

A CLI é uma casca fina sobre a biblioteca. Nunca muta os dados de origem; o ``report`` só
escreve no diretório de saída escolhido.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .loader import DataError, load_dataset
from .report import build_report, headline_metrics, render_markdown


def _cmd_validate(args: argparse.Namespace) -> int:
    ds = load_dataset(args.data)
    print(
        f"OK: {len(ds.accounts)} accounts, {len(ds.identities)} identities, "
        f"{len(ds.entitlements)} entitlements, {len(ds.groups)} groups, {len(ds.roles)} roles."
    )
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    ds = load_dataset(args.data)
    metrics = headline_metrics(ds)
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    ds = load_dataset(args.data)
    report = build_report(ds)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "governance.report.json"
    md_path = out_dir / "governance.report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render_markdown(ds), encoding="utf-8")
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import os

    import uvicorn

    os.environ["IAMGOV_DATA_DIR"] = str(args.data)
    uvicorn.run("iamgov.api:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iamgov", description="Lab de governança IAM/IGA (read-only)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_data(p: argparse.ArgumentParser) -> None:
        p.add_argument("--data", default="data", help="diretório de dados (padrão: data)")

    p_validate = sub.add_parser("validate", help="carrega e valida o dataset")
    add_data(p_validate)
    p_validate.set_defaults(func=_cmd_validate)

    p_scan = sub.add_parser("scan", help="imprime as headline metrics em JSON")
    add_data(p_scan)
    p_scan.set_defaults(func=_cmd_scan)

    p_report = sub.add_parser("report", help="gera os reports em JSON + Markdown")
    add_data(p_report)
    p_report.add_argument("--out", default="out", help="diretório de saída (padrão: out)")
    p_report.set_defaults(func=_cmd_report)

    p_serve = sub.add_parser("serve", help="sobe a API + dashboard")
    add_data(p_serve)
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true", help="auto-reload ao mudar o código")
    p_serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result: int = args.func(args)
        return result
    except DataError as exc:
        print(f"data error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
