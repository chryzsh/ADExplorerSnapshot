#!/usr/bin/env python3
# Generate a static HTML report from run_all.py output

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import json
from html import escape
from pathlib import Path

from viewer import load_data


def prepare_sections(sections, max_rows):
    prepared = {}
    for key in sorted(sections.keys()):
        headers = sections[key].get("headers", [])
        rows = sections[key].get("rows", [])
        total_rows = len(rows)

        if max_rows > 0:
            shown_rows = rows[:max_rows]
        else:
            shown_rows = rows

        prepared[key] = {
            "headers": headers,
            "rows": shown_rows,
            "total_rows": total_rows,
            "omitted_rows": max(0, total_rows - len(shown_rows)),
        }

    return prepared


def render_report(sections, title, max_rows):
    prepared_sections = prepare_sections(sections, max_rows)
    section_count = len(prepared_sections)
    total_rows = sum(s.get("total_rows", 0) for s in prepared_sections.values())
    data_json = json.dumps(prepared_sections).replace("</", "<\\/")

    template = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>__TITLE__</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: "Segoe UI", Tahoma, sans-serif;
      background: #eef1f5;
      color: #18212b;
      margin: 0;
      padding: 16px;
    }
    .meta {
      background: #ffffff;
      border: 1px solid #d8dde6;
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 12px;
    }
    .meta h1 {
      margin: 0;
      font-size: 20px;
    }
    .meta p {
      margin: 6px 0 0;
      color: #4b5563;
      font-size: 14px;
    }
    .layout {
      display: grid;
      grid-template-columns: 280px 1fr;
      gap: 12px;
      min-height: calc(100vh - 110px);
    }
    #sidebar {
      background: #ffffff;
      border: 1px solid #d8dde6;
      border-radius: 8px;
      padding: 10px;
      overflow: auto;
    }
    .nav-title {
      font-size: 12px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin: 8px 6px 4px;
    }
    .nav-item {
      padding: 8px 10px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
      color: #1f2937;
      margin: 0;
    }
    .nav-item:hover {
      background: #f1f5f9;
    }
    .nav-item.active {
      background: #dbeafe;
      color: #0f172a;
      font-weight: 600;
    }
    #main {
      background: #ffffff;
      border: 1px solid #d8dde6;
      border-radius: 8px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    #toolbar {
      border-bottom: 1px solid #e2e8f0;
      padding: 10px 12px;
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    #section-title {
      margin: 0;
      font-size: 16px;
      color: #0f172a;
    }
    #search {
      margin-left: auto;
      min-width: 220px;
      padding: 6px 10px;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      font-size: 13px;
    }
    #count {
      font-size: 12px;
      color: #64748b;
      white-space: nowrap;
    }
    #table-wrap {
      overflow: auto;
      padding: 10px 12px;
      flex: 1;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      border: 1px solid #e5e7eb;
      padding: 6px 8px;
      text-align: left;
      vertical-align: top;
      word-break: break-word;
    }
    th {
      background: #f3f4f6;
      position: sticky;
      top: 0;
      cursor: pointer;
      user-select: none;
    }
    .note {
      font-size: 12px;
      color: #6b7280;
      margin-top: 8px;
    }
    .empty {
      color: #64748b;
      font-size: 14px;
      padding: 20px 8px;
    }
    @media (max-width: 900px) {
      .layout {
        grid-template-columns: 1fr;
        min-height: auto;
      }
      #search {
        margin-left: 0;
        width: 100%;
      }
    }
  </style>
</head>
<body>
  <div class="meta">
    <h1>__TITLE__</h1>
    <p>__SECTION_COUNT__ sections, __TOTAL_ROWS__ rows</p>
  </div>
  <div class="layout">
    <aside id="sidebar">
      <div id="nav"></div>
    </aside>
    <div id="main">
      <div id="toolbar">
        <h2 id="section-title">Select a section</h2>
        <input id="search" type="text" placeholder="Filter rows...">
        <span id="count"></span>
      </div>
      <div id="table-wrap">
        <div class="empty">Select a section from the left navigation.</div>
      </div>
    </div>
  </div>

  <script>
    const DATA = __DATA__;
    const navEl = document.getElementById("nav");
    const titleEl = document.getElementById("section-title");
    const searchEl = document.getElementById("search");
    const countEl = document.getElementById("count");
    const tableWrapEl = document.getElementById("table-wrap");

    let currentKey = null;
    let sortCol = -1;
    let sortAsc = true;

    const groups = {};
    Object.keys(DATA).forEach((key) => {
      const parts = key.split("/");
      const group = parts.length > 1 ? parts[0] : "general";
      const name = parts.length > 1 ? parts[1] : parts[0];
      if (!groups[group]) groups[group] = [];
      groups[group].push({ key, name });
    });

    function renderNav() {
      const items = [];
      Object.keys(groups).sort().forEach((group) => {
        items.push(`<div class="nav-title">${esc(group)}</div>`);
        groups[group].sort((a, b) => a.name.localeCompare(b.name)).forEach((item) => {
          const rowCount = DATA[item.key].total_rows || 0;
          items.push(
            `<div class="nav-item" data-key="${esc(item.key)}">${esc(item.name)} <span class="note">(${rowCount})</span></div>`
          );
        });
      });

      navEl.innerHTML = items.join("");
      navEl.querySelectorAll(".nav-item").forEach((el) => {
        el.addEventListener("click", () => {
          selectSection(el.getAttribute("data-key"), el);
        });
      });
    }

    function selectSection(key, navElement) {
      currentKey = key;
      sortCol = -1;
      sortAsc = true;
      searchEl.value = "";

      document.querySelectorAll(".nav-item").forEach((el) => el.classList.remove("active"));
      if (navElement) navElement.classList.add("active");

      titleEl.textContent = key;
      renderTable();
    }

    function renderTable() {
      if (!currentKey) return;
      const section = DATA[currentKey];
      const headers = section.headers || [];
      const rows = section.rows || [];
      const totalRows = section.total_rows || rows.length;
      const omittedRows = section.omitted_rows || 0;

      const filter = searchEl.value.toLowerCase();
      let filtered = rows;
      if (filter) {
        filtered = rows.filter((row) =>
          row.some((cell) => String(cell).toLowerCase().includes(filter))
        );
      }

      if (sortCol >= 0) {
        filtered = [...filtered].sort((a, b) => {
          const va = String(a[sortCol] ?? "");
          const vb = String(b[sortCol] ?? "");
          return sortAsc
            ? va.localeCompare(vb, undefined, { numeric: true })
            : vb.localeCompare(va, undefined, { numeric: true });
        });
      }

      countEl.textContent = `${filtered.length} / ${totalRows} rows`;

      if (!headers.length) {
        tableWrapEl.innerHTML = '<div class="empty">No columns detected in this section.</div>';
        return;
      }

      let html = "<table><thead><tr>";
      headers.forEach((header, index) => {
        const arrow = sortCol === index ? (sortAsc ? " ▲" : " ▼") : "";
        html += `<th onclick="sortBy(${index})">${esc(header)}${arrow}</th>`;
      });
      html += "</tr></thead><tbody>";

      if (!filtered.length) {
        html += `<tr><td colspan="${headers.length}">No rows match the current filter.</td></tr>`;
      } else {
        filtered.forEach((row) => {
          html += "<tr>";
          const padded = [...row];
          while (padded.length < headers.length) padded.push("");
          padded.slice(0, headers.length).forEach((cell) => {
            html += `<td>${esc(cell)}</td>`;
          });
          html += "</tr>";
        });
      }

      html += "</tbody></table>";
      if (omittedRows > 0) {
        html += `<div class="note">Report export truncated this section by ${omittedRows} rows (use --max-rows 0 to include all).</div>`;
      }

      tableWrapEl.innerHTML = html;
    }

    function sortBy(column) {
      if (sortCol === column) sortAsc = !sortAsc;
      else {
        sortCol = column;
        sortAsc = true;
      }
      renderTable();
    }

    function esc(value) {
      return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    window.sortBy = sortBy;
    searchEl.addEventListener("input", renderTable);
    renderNav();

    const firstNav = document.querySelector(".nav-item");
    if (firstNav) {
      selectSection(firstNav.getAttribute("data-key"), firstNav);
    }
  </script>
</body>
</html>
"""

    return (
        template
        .replace("__TITLE__", escape(title))
        .replace("__SECTION_COUNT__", str(section_count))
        .replace("__TOTAL_ROWS__", str(total_rows))
        .replace("__DATA__", data_json)
    )


def main():
    parser = argparse.ArgumentParser(description="Generate a static tabbed HTML report from run_all.py output")
    parser.add_argument("dump_dir", help="Path to the snapshot-dump output folder")
    parser.add_argument("-o", "--output", default="snapshot_report.html", help="Output HTML file (default: snapshot_report.html)")
    parser.add_argument("--title", default="AD Explorer Snapshot Report", help="HTML report title")
    parser.add_argument("--max-rows", type=int, default=2000, help="Maximum rows per section in exported report (0 = all, default: 2000)")
    args = parser.parse_args()

    dump_dir = Path(args.dump_dir)
    if not dump_dir.is_dir():
        print(f"[-] Not a directory: {dump_dir}")
        sys.exit(1)

    if args.max_rows < 0:
        print("[-] --max-rows must be >= 0")
        sys.exit(1)

    print(f"[*] Loading data from {dump_dir}...")
    sections = load_data(str(dump_dir))
    print(f"[+] Loaded {len(sections)} sections")

    html = render_report(sections, args.title, args.max_rows)
    output_path = Path(args.output)
    output_path.write_text(html, encoding="utf-8")
    print(f"[+] Report written to {output_path}")


if __name__ == "__main__":
    main()
