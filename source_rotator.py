"""Daemon: compress cold contract sources so the hot set stays ~FOMO_SOURCE_HOT_GB."""

from __future__ import annotations

import argparse
import os
import time

from contract_archive import DEFAULT_CONTRACTS, DEFAULT_HOT_GB, DEFAULT_MIN_AGE_HOURS, rotate_sources


def _log(msg: str) -> None:
    print(f"[source_rotator] {msg}", flush=True)


def run_once(args: argparse.Namespace) -> dict:
    hot_bytes = int(args.hot_gb * (1024**3))
    min_age = args.min_age_hours * 3600
    stats = rotate_sources(
        args.contracts_dir,
        hot_bytes=hot_bytes,
        min_age_seconds=min_age,
    )
    _log(
        "hot={hot:.2f}G/{lim:.2f}G archived={n} freed={freed:.2f}G "
        "already={a} skip_young={y} skip_triage={k}".format(
            hot=stats["hot_bytes"] / (1024**3),
            lim=stats["hot_limit"] / (1024**3),
            n=stats["archived"],
            freed=stats["freed_bytes"] / (1024**3),
            a=stats["already_archived"],
            y=stats["skipped_young"],
            k=stats["skipped_keep"],
        )
    )
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Rotate FOMO contract sources to tar.gz")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=int(os.environ.get("FOMO_ROTATE_INTERVAL", "3600")))
    parser.add_argument("--contracts-dir", default=DEFAULT_CONTRACTS)
    parser.add_argument("--hot-gb", type=float, default=DEFAULT_HOT_GB)
    parser.add_argument("--min-age-hours", type=float, default=DEFAULT_MIN_AGE_HOURS)
    args = parser.parse_args()
    if args.daemon:
        _log(
            f"daemon interval={args.interval}s hot_gb={args.hot_gb} "
            f"min_age_h={args.min_age_hours} dir={args.contracts_dir}"
        )
        while True:
            try:
                run_once(args)
            except Exception as exc:
                _log(f"error {type(exc).__name__}: {exc}")
            time.sleep(max(60, args.interval))
    else:
        run_once(args)


if __name__ == "__main__":
    main()
