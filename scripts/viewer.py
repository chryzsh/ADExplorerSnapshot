#!/usr/bin/env python3
# Simple web viewer for run_all.py output
# Usage: python3 viewer.py /path/to/snapshot-dump

import sys, os
import argparse
import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

def parse_delimited(filepath):
    """Parse ||-delimited files with header row."""
    lines = filepath.read_text().strip().splitlines()
    if not lines:
        return [], []
    headers = [h.strip() for h in lines[0].split("||")]
    rows = []
    for line in lines[1:]:
        row = [c.strip() for c in line.split("||")]
        # pad short rows
        while len(row) < len(headers):
            row.append("")
        rows.append(row)
    return headers, rows

def parse_block(filepath):
    """Parse block-formatted files (certs, gpo) into list of dicts."""
    text = filepath.read_text().strip()
    if not text:
        return [], []

    blocks = []
    current = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("---") or line == "-----------------------------------------":
            if current:
                blocks.append(current)
                current = {}
            continue
        if ":" in line and not line.startswith("{"):
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key in current:
                current[key] += "\n" + val
            else:
                current[key] = val
        elif current:
            # continuation line (e.g. aces)
            last_key = list(current.keys())[-1] if current else None
            if last_key:
                current[last_key] += "\n" + line
    if current:
        blocks.append(current)

    if not blocks:
        return [], []
    all_keys = []
    seen = set()
    for b in blocks:
        for k in b:
            if k not in seen:
                all_keys.append(k)
                seen.add(k)
    rows = []
    for b in blocks:
        rows.append([b.get(k, "") for k in all_keys])
    return all_keys, rows

def parse_lines(filepath):
    """Parse freeform text files as single-column data."""
    lines = filepath.read_text().strip().splitlines()
    lines = [l for l in lines if l.strip() and not l.startswith("[+]") and not l.startswith("[*]")]
    return ["value"], [[l.strip()] for l in lines]

def load_data(dump_dir):
    """Load all data from a snapshot-dump directory."""
    dump = Path(dump_dir)
    sections = {}

    # interesting/ folder - delimited files
    interesting = dump / "interesting"
    if interesting.is_dir():
        for f in sorted(interesting.glob("*.txt")):
            headers, rows = parse_delimited(f)
            if headers:
                sections[f"interesting/{f.stem}"] = {"headers": headers, "rows": rows}

    # certs/ and gpo/ - block files
    for subdir in ["certs", "gpo"]:
        d = dump / subdir
        if d.is_dir():
            for f in sorted(d.glob("*.txt")):
                headers, rows = parse_block(f)
                if headers:
                    sections[f"{subdir}/{f.stem}"] = {"headers": headers, "rows": rows}

    # top-level text files
    for f in sorted(dump.glob("*.txt")):
        if f.stat().st_size == 0:
            continue
        # try delimited first
        first_line = f.read_text().split("\n", 1)[0]
        if "||" in first_line:
            headers, rows = parse_delimited(f)
        elif " | " in first_line:
            # pipe-separated (phonenumbers)
            headers, rows = parse_pipe(f)
        else:
            headers, rows = parse_lines(f)
        if headers:
            sections[f.stem] = {"headers": headers, "rows": rows}

    return sections

def parse_pipe(filepath):
    """Parse pipe-separated files (phonenumbers)."""
    lines = filepath.read_text().strip().splitlines()
    lines = [l for l in lines if l.strip() and not l.startswith("[+]")]
    if not lines:
        return [], []
    # infer columns from first line
    ncols = len(lines[0].split(" | "))
    # phonenumbers has known headers
    if ncols == 6:
        headers = ["name", "phone", "title", "department", "samaccountname", "upn"]
    else:
        headers = [f"col{i}" for i in range(ncols)]
    rows = []
    for line in lines:
        parts = [p.strip() for p in line.split(" | ")]
        while len(parts) < len(headers):
            parts.append("")
        rows.append(parts)
    return headers, rows

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AD Explorer Snapshot Viewer</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #1e1e1e; color: #d4d4d4; display: flex; height: 100vh; }
#sidebar { width: 240px; background: #252526; padding: 12px; overflow-y: auto; flex-shrink: 0; border-right: 1px solid #333; }
#sidebar h2 { font-size: 14px; color: #ccc; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }
.nav-section { font-size: 11px; color: #888; text-transform: uppercase; margin-top: 12px; margin-bottom: 4px; letter-spacing: 1px; }
.nav-item { padding: 6px 10px; cursor: pointer; border-radius: 4px; font-size: 13px; margin-bottom: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.nav-item:hover { background: #333; }
.nav-item.active { background: #0078d4; color: white; }
#main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
#toolbar { padding: 12px 16px; background: #252526; border-bottom: 1px solid #333; display: flex; align-items: center; gap: 12px; }
#toolbar h3 { font-size: 16px; color: #ccc; }
#search { padding: 6px 12px; background: #1e1e1e; border: 1px solid #444; color: #d4d4d4; border-radius: 4px; width: 300px; font-size: 13px; }
#search:focus { outline: none; border-color: #0078d4; }
#count { font-size: 12px; color: #888; }
#table-wrap { flex: 1; overflow: auto; padding: 0 16px 16px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { position: sticky; top: 0; background: #252526; color: #ccc; text-align: left; padding: 8px 10px; border-bottom: 2px solid #444; cursor: pointer; user-select: none; white-space: nowrap; }
th:hover { background: #333; }
td { padding: 6px 10px; border-bottom: 1px solid #2d2d2d; max-width: 500px; word-break: break-all; }
tr:hover { background: #2a2d2e; }
.empty { padding: 40px; text-align: center; color: #888; }
</style>
</head>
<body>
<div id="sidebar">
  <h2>Snapshot</h2>
  <div id="nav"></div>
</div>
<div id="main">
  <div id="toolbar">
    <h3 id="title">Select a section</h3>
    <input type="text" id="search" placeholder="Filter rows...">
    <span id="count"></span>
  </div>
  <div id="table-wrap">
    <div class="empty">Select a section from the sidebar</div>
  </div>
</div>
<script>
const DATA = __DATA__;

const nav = document.getElementById('nav');
const tableWrap = document.getElementById('table-wrap');
const searchBox = document.getElementById('search');
const titleEl = document.getElementById('title');
const countEl = document.getElementById('count');

let currentKey = null;
let sortCol = -1;
let sortAsc = true;

// group sections
const groups = {};
Object.keys(DATA).forEach(k => {
  const parts = k.split('/');
  const group = parts.length > 1 ? parts[0] : 'general';
  const name = parts.length > 1 ? parts[1] : parts[0];
  if (!groups[group]) groups[group] = [];
  groups[group].push({key: k, name: name});
});

// render nav
Object.keys(groups).sort().forEach(group => {
  const sec = document.createElement('div');
  sec.className = 'nav-section';
  sec.textContent = group;
  nav.appendChild(sec);
  groups[group].forEach(item => {
    const div = document.createElement('div');
    div.className = 'nav-item';
    div.textContent = item.name + ' (' + DATA[item.key].rows.length + ')';
    div.onclick = () => selectSection(item.key, div);
    nav.appendChild(div);
  });
});

function selectSection(key, el) {
  currentKey = key;
  sortCol = -1;
  searchBox.value = '';
  document.querySelectorAll('.nav-item').forEach(e => e.classList.remove('active'));
  if (el) el.classList.add('active');
  titleEl.textContent = key;
  renderTable();
}

function renderTable() {
  if (!currentKey) return;
  const {headers, rows} = DATA[currentKey];
  const filter = searchBox.value.toLowerCase();

  let filtered = rows;
  if (filter) {
    filtered = rows.filter(r => r.some(c => c.toLowerCase().includes(filter)));
  }

  if (sortCol >= 0) {
    filtered = [...filtered].sort((a, b) => {
      const va = a[sortCol] || '', vb = b[sortCol] || '';
      return sortAsc ? va.localeCompare(vb, undefined, {numeric: true}) : vb.localeCompare(va, undefined, {numeric: true});
    });
  }

  countEl.textContent = filtered.length + ' / ' + rows.length + ' rows';

  let html = '<table><thead><tr>';
  headers.forEach((h, i) => {
    const arrow = sortCol === i ? (sortAsc ? ' ▲' : ' ▼') : '';
    html += '<th onclick="sortBy(' + i + ')">' + esc(h) + arrow + '</th>';
  });
  html += '</tr></thead><tbody>';

  // limit to 5000 rows for performance
  const limit = Math.min(filtered.length, 5000);
  for (let i = 0; i < limit; i++) {
    html += '<tr>';
    filtered[i].forEach(c => { html += '<td title="' + esc(c) + '">' + esc(c) + '</td>'; });
    html += '</tr>';
  }
  if (filtered.length > limit) {
    html += '<tr><td colspan="' + headers.length + '" style="text-align:center;color:#888">... ' + (filtered.length - limit) + ' more rows (filter to narrow down)</td></tr>';
  }
  html += '</tbody></table>';
  tableWrap.innerHTML = html;
}

function sortBy(col) {
  if (sortCol === col) sortAsc = !sortAsc;
  else { sortCol = col; sortAsc = true; }
  renderTable();
}

function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

searchBox.addEventListener('input', renderTable);

// auto-select first section
const firstKey = Object.keys(DATA)[0];
if (firstKey) {
  const firstNav = document.querySelector('.nav-item');
  selectSection(firstKey, firstNav);
}
</script>
</body>
</html>"""

class ViewerHandler(SimpleHTTPRequestHandler):
    html_content = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(self.html_content.encode())

    def log_message(self, format, *args):
        pass  # quiet

def main():
    parser = argparse.ArgumentParser(description="Web viewer for ADExplorerSnapshot dump output")
    parser.add_argument("dump_dir", help="Path to the snapshot-dump output folder")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port to serve on (default: 80)")
    parser.add_argument("--html", help="Export to static HTML file instead of serving")
    args = parser.parse_args()

    if not Path(args.dump_dir).is_dir():
        print(f"[-] Not a directory: {args.dump_dir}")
        sys.exit(1)

    print(f"[*] Loading data from {args.dump_dir}...")
    sections = load_data(args.dump_dir)
    print(f"[+] Loaded {len(sections)} sections, {sum(len(s['rows']) for s in sections.values())} total rows")

    data_json = json.dumps(sections)
    html = HTML_TEMPLATE.replace("__DATA__", data_json)

    if args.html:
        Path(args.html).write_text(html)
        print(f"[+] Written to {args.html}")
        return

    ViewerHandler.html_content = html
    server = HTTPServer(("0.0.0.0", args.port), ViewerHandler)
    print(f"[+] Serving at http://0.0.0.0:{args.port}")
    print(f"    Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped")

if __name__ == "__main__":
    main()
