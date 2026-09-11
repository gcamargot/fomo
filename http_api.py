#!/usr/bin/env python3
"""LAN dashboard + JSON API for pipeline stats and triage verdicts."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional, Tuple
from urllib.parse import urlparse

from pipeline_stats import collect_pipeline_stats

DEFAULT_BIND = os.environ.get("FOMO_API_BIND", "0.0.0.0")
DEFAULT_PORT = int(os.environ.get("FOMO_API_PORT", "8787"))
DB_PATH = os.environ.get("FOMO_DB_PATH", "./contracts/token_research_dataset.db")
TRIAGE_DIR = os.environ.get("FOMO_TRIAGE_DIR", "./contracts/triage_queue")
ARCHIVE_DIR = os.environ.get("FOMO_ARCHIVE_DIR", "./contracts/triage_archive")
API_TOKEN = os.environ.get("FOMO_API_TOKEN", "").strip()

_ADDR_RE = re.compile(r"^(0x[0-9a-fA-F]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})$")
_CHAIN_RE = re.compile(r"^[a-z0-9]{2,16}$")
_NOTE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    try:
        conn.execute("PRAGMA busy_timeout=30000")
    except sqlite3.Error:
        pass
    return conn


def _json_body(data: Any, status: int = 200) -> Tuple[int, bytes, str]:
    raw = json.dumps(data, default=str).encode("utf-8")
    return status, raw, "application/json; charset=utf-8"


def _text_body(text: str, status: int = 200, ctype: str = "text/plain; charset=utf-8") -> Tuple[int, bytes, str]:
    return status, text.encode("utf-8"), ctype


def _card_path(root: str, chain: str, address: str) -> Optional[str]:
    if not _CHAIN_RE.match(chain) or not _ADDR_RE.match(address):
        return None
    name = f"triage_{chain}_{address.lower()}.md"
    path = os.path.abspath(os.path.join(root, name))
    root_abs = os.path.abspath(root)
    if not path.startswith(root_abs + os.sep):
        return None
    return path if os.path.isfile(path) else None


def apply_triage(chain: str, address: str, verdict: str, note: str = "") -> Tuple[int, dict]:
    """Mark a hit TP/FP: update SQLite and archive the markdown card."""
    chain = (chain or "").lower()
    address = (address or "").lower()
    if not _CHAIN_RE.match(chain) or not _ADDR_RE.match(address):
        return 400, {"error": "bad_address"}
    v = (verdict or "").strip().upper()
    if v not in ("TP", "FP"):
        return 400, {"error": "verdict_must_be_TP_or_FP"}
    note = (note or "").strip()[:200]
    now = datetime.now(timezone.utc).isoformat()
    if v == "TP":
        status = "TRIAGED_TP"
        fields = {
            "dynamic_status": status,
            "is_user_exploitable": 1,
            "triage_file_path": None,
            "last_checked_at": now,
        }
    else:
        slug = _NOTE_RE.sub("_", note.upper()).strip("_")[:32] or "TRIAGED"
        status = slug if slug.startswith("FP_") else f"FP_{slug}"
        fields = {
            "dynamic_status": status,
            "is_user_exploitable": 0,
            "expected_profit_eth": None,
            "triage_file_path": None,
            "last_checked_at": now,
        }

    extra = ", expected_profit_eth=NULL" if v == "FP" else ""
    sql = (
        "UPDATE tokens SET dynamic_status=?, is_user_exploitable=?, "
        f"triage_file_path=NULL, last_checked_at=?{extra} "
    )
    params_chain = (fields["dynamic_status"], fields["is_user_exploitable"], now, address, chain)
    params_addr = (fields["dynamic_status"], fields["is_user_exploitable"], now, address)
    conn = _db()
    try:
        cur = conn.execute(sql + "WHERE lower(address)=? AND IFNULL(chain,'')=?", params_chain)
        if cur.rowcount == 0:
            conn.execute(sql + "WHERE lower(address)=?", params_addr)
        conn.commit()
    finally:
        conn.close()

    moved = False
    src = _card_path(TRIAGE_DIR, chain, address)
    if src:
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        dst = os.path.join(ARCHIVE_DIR, os.path.basename(src))
        with open(src, "a", encoding="utf-8") as fh:
            fh.write(f"\n\n---\n### Dashboard verdict ({now})\n- {v} `{status}` {note}\n")
        shutil.move(src, dst)
        moved = True
    return 200, {"ok": True, "verdict": v, "status": status, "archived": moved, "address": address, "chain": chain}


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>FOMO pipeline</title>
<style>
  :root { color-scheme: dark; }
  body { font: 15px/1.45 system-ui, sans-serif; margin: 0; background: #111; color: #eee; }
  header { padding: 16px 20px; background: #1a1a1a; border-bottom: 1px solid #333; }
  h1 { font-size: 18px; margin: 0 0 4px; }
  main { padding: 16px 20px 40px; max-width: 1100px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 10px; margin: 12px 0 24px; }
  .card { background: #1c1c1c; border: 1px solid #333; border-radius: 8px; padding: 10px 12px; }
  .card b { display: block; font-size: 22px; }
  .card span { color: #999; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid #2a2a2a; vertical-align: top; }
  th { color: #aaa; font-weight: 600; }
  code { font-size: 12px; }
  button { cursor: pointer; margin-right: 6px; padding: 4px 10px; border-radius: 4px; border: 0; }
  .tp { background: #1b5; color: #041; }
  .fp { background: #b45; color: #fff; }
  textarea, input { background: #111; color: #eee; border: 1px solid #444; border-radius: 4px; padding: 4px; }
  .muted { color: #888; }
  pre { white-space: pre-wrap; background: #0a0a0a; padding: 10px; border-radius: 6px; max-height: 280px; overflow: auto; }
  .err { color: #f66; }
</style>
</head>
<body>
<header>
  <h1>FOMO profit pipeline</h1>
  <div class="muted" id="meta">cargando…</div>
</header>
<main>
  <div class="grid" id="kpis"></div>
  <h2>Cola de triage</h2>
  <p class="muted">TP = verdadero positivo (queda como hit). FP = falso, sale de la cola y la DB.</p>
  <div id="queue"></div>
  <h2>Top expected profit</h2>
  <div id="top"></div>
</main>
<script>
async function j(url, opt) {
  const r = await fetch(url, opt);
  const t = await r.text();
  try { return JSON.parse(t); } catch { return { error: t, status: r.status }; }
}
function kpi(label, n) {
  return `<div class="card"><b>${n}</b><span>${label}</span></div>`;
}
async function mark(chain, addr, verdict) {
  const note = document.getElementById('note-'+addr)?.value || '';
  const res = await j('/triage/'+chain+'/'+addr, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ verdict, note })
  });
  if (!res.ok) { alert(res.error || JSON.stringify(res)); return; }
  load();
}
async function load() {
  const s = await j('/stats');
  if (s.error) { document.getElementById('meta').textContent = s.error; return; }
  const h = s.hits || {}, w = s.watchlist || {}, f = s.factory || {}, c = s.corpus || {};
  document.getElementById('meta').textContent =
    'corpus ' + (c.total||0) + ' · min ' + (h.min_profit_eth||0.05) + ' ETH · ' + new Date().toLocaleString();
  document.getElementById('kpis').innerHTML = [
    kpi('pending', h.pending_review||0),
    kpi('profit PASS', h.profit_pass||0),
    kpi('confirmed', h.confirmed||0),
    kpi('near-miss', w.near_miss||0),
    kpi('sleeping tax', w.sleeping_tax||0),
    kpi('unfunded', w.unfunded_drain||0),
    kpi('factory', (f.total||0) + ' / act ' + (f.actionable||0)),
  ].join('');
  const q = (h.queue||[]);
  if (!q.length) {
    document.getElementById('queue').innerHTML = '<p class="muted">Nada en contracts/triage_queue.</p>';
  } else {
    document.getElementById('queue').innerHTML = '<table><tr><th>addr</th><th>chain</th><th>ETH</th><th></th></tr>' +
      q.map(row => {
        const a = row.address||'', ch = row.chain||'';
        return `<tr>
          <td><code>${a}</code></td><td>${ch}</td>
          <td>${(row.expected_profit_eth||0).toFixed(4)}</td>
          <td>
            <input id="note-${a}" placeholder="nota FP" size="16"/>
            <button class="tp" onclick="mark('${ch}','${a}','TP')">TP</button>
            <button class="fp" onclick="mark('${ch}','${a}','FP')">FP</button>
          </td></tr>`;
      }).join('') + '</table>';
  }
  const top = s.top_expected_profit||[];
  document.getElementById('top').innerHTML = top.length
    ? '<table><tr><th>addr</th><th>chain</th><th>ETH</th><th>status</th></tr>' +
      top.map(r => `<tr><td><code>${r.address}</code></td><td>${r.chain}</td>
        <td>${(r.expected_profit_eth||0).toFixed(4)}</td>
        <td class="muted">${(r.dynamic_status||'').slice(0,80)}</td></tr>`).join('') + '</table>'
    : '<p class="muted">Sin filas de profit.</p>';
}
load();
setInterval(load, 15000);
</script>
</body>
</html>
"""


def dispatch(
    method: str,
    path: str,
    token: str = "",
    body: Optional[bytes] = None,
) -> Tuple[int, bytes, str]:
    """Pure router for tests. Returns (status, body, content_type)."""
    if API_TOKEN and token != API_TOKEN:
        return _json_body({"error": "unauthorized"}, 401)

    parsed = urlparse(path)
    route = parsed.path.rstrip("/") or "/"

    if method == "GET" and route == "/":
        return 200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8"

    if method == "GET" and route in ("/health", "/healthz"):
        return _json_body({"ok": True, "service": "fomo"})

    if method == "GET" and route == "/stats":
        conn = _db()
        try:
            return _json_body(collect_pipeline_stats(conn, triage_dir=TRIAGE_DIR))
        finally:
            conn.close()

    if method == "GET" and route == "/triage":
        conn = _db()
        try:
            stats = collect_pipeline_stats(conn, triage_dir=TRIAGE_DIR)
        finally:
            conn.close()
        return _json_body({"queue": stats["hits"]["queue"], "count": stats["hits"]["pending_review"]})

    if route.startswith("/triage/"):
        parts = route.split("/")
        if len(parts) != 4:
            return _json_body({"error": "not_found"}, 404)
        _, _, chain, address = parts
        if method == "GET":
            for root in (TRIAGE_DIR, ARCHIVE_DIR):
                card = _card_path(root, chain.lower(), address.lower())
                if card:
                    with open(card, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read(120_000)
                    return _text_body(text, ctype="text/markdown; charset=utf-8")
            return _json_body({"error": "not_found"}, 404)
        if method == "POST":
            payload: dict = {}
            if body:
                try:
                    payload = json.loads(body.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return _json_body({"error": "bad_json"}, 400)
            st, data = apply_triage(
                chain,
                address,
                str(payload.get("verdict") or ""),
                str(payload.get("note") or ""),
            )
            return _json_body(data, st)
        return _json_body({"error": "method_not_allowed"}, 405)

    if method != "GET":
        return _json_body({"error": "method_not_allowed"}, 405)
    return _json_body({"error": "not_found"}, 404)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return self.headers.get("X-FOMO-Token", "").strip()

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return b""
        return self.rfile.read(min(n, 32_000))

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        try:
            status, body, ctype = dispatch("GET", self.path, self._token())
        except sqlite3.Error as exc:
            status, body, ctype = _json_body({"error": "db", "detail": str(exc)}, 503)
        except Exception as exc:
            status, body, ctype = _json_body({"error": "internal", "detail": str(exc)}, 500)
        self._send(status, body, ctype)

    def do_POST(self) -> None:  # noqa: N802
        try:
            status, body, ctype = dispatch(
                "POST", self.path, self._token(), body=self._read_body()
            )
        except sqlite3.Error as exc:
            status, body, ctype = _json_body({"error": "db", "detail": str(exc)}, 503)
        except Exception as exc:
            status, body, ctype = _json_body({"error": "internal", "detail": str(exc)}, 500)
        self._send(status, body, ctype)


def serve(bind: str = DEFAULT_BIND, port: int = DEFAULT_PORT) -> None:
    httpd = ThreadingHTTPServer((bind, port), Handler)
    print(f"[http_api] listening on http://{bind}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="FOMO LAN dashboard + API")
    parser.add_argument("--bind", default=DEFAULT_BIND)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--db", default=None)
    parser.add_argument("--triage", default=None)
    args = parser.parse_args()
    global DB_PATH, TRIAGE_DIR
    if args.db:
        DB_PATH = args.db
    if args.triage:
        TRIAGE_DIR = args.triage
    serve(args.bind, args.port)


if __name__ == "__main__":
    main()
