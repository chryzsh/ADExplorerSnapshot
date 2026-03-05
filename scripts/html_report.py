#!/usr/bin/env python3
# Generate a static HTML report from run_all.py output

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from html import escape
from pathlib import Path

from viewer import load_data


def render_report(sections, title, max_rows):
    section_count = len(sections)
    total_rows = sum(len(s.get("rows", [])) for s in sections.values())

    nav_items = []
    section_blocks = []

    for idx, key in enumerate(sorted(sections.keys())):
        anchor = f"sec-{idx}"
        headers = sections[key].get("headers", [])
        rows = sections[key].get("rows", [])

        nav_items.append(
            f'<li><a href="#{anchor}">{escape(key)}</a> '
            f'<span class="count">{len(rows)} rows</span></li>'
        )

        if max_rows > 0:
            shown_rows = rows[:max_rows]
            remaining = len(rows) - len(shown_rows)
        else:
            shown_rows = rows
            remaining = 0

        table_html = []
        table_html.append("<table>")
        table_html.append("<thead><tr>")
        for h in headers:
            table_html.append(f"<th>{escape(str(h))}</th>")
        table_html.append("</tr></thead>")
        table_html.append("<tbody>")
        for row in shown_rows:
            table_html.append("<tr>")
            padded = list(row) + [""] * max(0, len(headers) - len(row))
            for cell in padded[:len(headers)]:
                table_html.append(f"<td>{escape(str(cell))}</td>")
            table_html.append("</tr>")
        table_html.append("</tbody>")
        table_html.append("</table>")

        more_html = ""
        if remaining > 0:
            more_html = (
                f'<p class="note">Showing first {len(shown_rows)} rows '
                f"out of {len(rows)}. {remaining} omitted.</p>"
            )

        if not headers:
            section_table = '<p class="note">No columns detected in this section.</p>'
        else:
            section_table = "".join(table_html) + more_html

        section_blocks.append(
            f"""
<section id="{anchor}">
  <h2>{escape(key)} <span class="count">{len(rows)} rows</span></h2>
  {section_table}
</section>
"""
        )

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{escape(title)}</title>
  <style>
    body {{
      font-family: "Segoe UI", Tahoma, sans-serif;
      background: #f6f7f9;
      color: #1a1d21;
      margin: 0;
      padding: 24px;
    }}
    .wrap {{
      max-width: 1300px;
      margin: 0 auto;
    }}
    .meta {{
      background: #ffffff;
      border: 1px solid #d8dde6;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 18px;
    }}
    .meta h1 {{
      margin: 0 0 8px;
      font-size: 22px;
    }}
    .meta p {{
      margin: 0;
      color: #4b5563;
      font-size: 14px;
    }}
    nav {{
      background: #ffffff;
      border: 1px solid #d8dde6;
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 18px;
    }}
    nav ul {{
      list-style: none;
      margin: 0;
      padding: 0;
      columns: 2;
      gap: 24px;
    }}
    nav li {{
      margin: 4px 0;
      font-size: 14px;
    }}
    nav a {{
      color: #005fb8;
      text-decoration: none;
    }}
    nav a:hover {{
      text-decoration: underline;
    }}
    section {{
      background: #ffffff;
      border: 1px solid #d8dde6;
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 16px;
      overflow-x: auto;
    }}
    h2 {{
      margin: 0 0 10px;
      font-size: 18px;
    }}
    .count {{
      color: #6b7280;
      font-size: 12px;
      font-weight: 500;
      margin-left: 6px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      border: 1px solid #e5e7eb;
      padding: 6px 8px;
      text-align: left;
      vertical-align: top;
      word-break: break-word;
    }}
    th {{
      background: #f3f4f6;
      position: sticky;
      top: 0;
    }}
    .note {{
      font-size: 12px;
      color: #6b7280;
      margin-top: 8px;
    }}
    @media (max-width: 900px) {{
      nav ul {{
        columns: 1;
      }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="meta">
      <h1>{escape(title)}</h1>
      <p>{section_count} sections, {total_rows} rows</p>
    </div>
    <nav>
      <ul>
        {"".join(nav_items)}
      </ul>
    </nav>
    {"".join(section_blocks)}
  </div>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Generate a static HTML report from run_all.py output")
    parser.add_argument("dump_dir", help="Path to the snapshot-dump output folder")
    parser.add_argument("-o", "--output", default="snapshot_report.html", help="Output HTML file (default: snapshot_report.html)")
    parser.add_argument("--title", default="AD Explorer Snapshot Report", help="HTML report title")
    parser.add_argument("--max-rows", type=int, default=2000, help="Maximum rows per section (0 = all, default: 2000)")
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
