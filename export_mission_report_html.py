from html import escape
from pathlib import Path
import re

INPUT = Path('mission_control_report.md')
OUTPUT = Path('mission_control_report.html')


def slugify_heading(text: str) -> str:
    slug = re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')
    return slug or 'section'


def format_inline(text: str) -> str:
    escaped = escape(text)
    escaped = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', escaped)
    escaped = re.sub(r'\*(.+?)\*', r'<em>\1</em>', escaped)
    return escaped


def is_table_divider(line: str) -> bool:
    parts = [part.strip() for part in line.strip().strip('|').split('|')]
    return bool(parts) and all(part and set(part) <= {'-', ':'} for part in parts)


def linkify_scenario_cell(header: str, cell: str) -> str:
    text_value = re.sub(r'<[^>]+>', '', cell).strip()
    if header.lower() != 'scenario' or not text_value.startswith('SCENARIO'):
        return cell
    return f'<a class="scenario-link" href="dashboard/index.html?scenario={escape(text_value)}">{cell}</a>'


def maybe_dashboard_link(title: str) -> str:
    if not title.startswith('SCENARIO'):
        return ''
    return f' <a class="dashboard-backlink" href="dashboard/index.html?scenario={escape(title)}">Open in Dashboard</a>'


def render_table(lines: list[str]) -> list[str]:
    rows = [[format_inline(cell.strip()) for cell in line.strip().strip('|').split('|')] for line in lines]
    if len(rows) < 2 or not is_table_divider(lines[1]):
        return [f'<pre>{escape(line)}</pre>' for line in lines]

    header = rows[0]
    body = rows[2:]
    html = ['<div class="table-wrap"><table>']
    html.append('<thead><tr>' + ''.join(f'<th>{cell}</th>' for cell in header) + '</tr></thead>')
    html.append('<tbody>')
    for row in body:
        padded = row + [''] * (len(header) - len(row))
        decorated = [linkify_scenario_cell(column, cell) for column, cell in zip(header, padded[:len(header)])]
        html.append('<tr>' + ''.join(f'<td>{cell}</td>' for cell in decorated) + '</tr>')
    html.append('</tbody></table></div>')
    return html


def render_blocks(lines: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    html = []
    nav_items: list[tuple[str, str]] = []
    paragraph: list[str] = []
    bullet_list: list[str] = []
    table_lines: list[str] = []
    heading_counts: dict[str, int] = {}

    def heading_id(text: str) -> str:
        base = slugify_heading(text)
        count = heading_counts.get(base, 0)
        heading_counts[base] = count + 1
        return base if count == 0 else f'{base}-{count + 1}'

    def flush_paragraph() -> None:
        if paragraph:
            html.append(f'<p>{format_inline(" ".join(paragraph))}</p>')
            paragraph.clear()

    def flush_list() -> None:
        if bullet_list:
            html.append('<ul>')
            html.extend(f'<li>{format_inline(item)}</li>' for item in bullet_list)
            html.append('</ul>')
            bullet_list.clear()

    def flush_table() -> None:
        if table_lines:
            html.extend(render_table(table_lines))
            table_lines.clear()

    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()

        if line.startswith('|'):
            flush_paragraph()
            flush_list()
            table_lines.append(line)
            continue

        flush_table()

        if not stripped:
            flush_paragraph()
            flush_list()
            continue

        if stripped == '---':
            flush_paragraph()
            flush_list()
            html.append('<hr>')
            continue

        if stripped.startswith('### '):
            flush_paragraph()
            flush_list()
            title = stripped[4:]
            html.append(f'<h3 id="{heading_id(title)}">{format_inline(title)}{maybe_dashboard_link(title)}</h3>')
            continue

        if stripped.startswith('## '):
            flush_paragraph()
            flush_list()
            title = stripped[3:]
            current_id = heading_id(title)
            nav_items.append((title, current_id))
            html.append(f'<h2 id="{current_id}">{format_inline(title)}</h2>')
            continue

        if stripped.startswith('# '):
            flush_paragraph()
            flush_list()
            title = stripped[2:]
            html.append(f'<h1 id="{heading_id(title)}">{format_inline(title)}</h1>')
            continue

        if stripped.startswith('- '):
            flush_paragraph()
            bullet_list.append(stripped[2:])
            continue

        paragraph.append(stripped)

    flush_table()
    flush_paragraph()
    flush_list()
    return html, nav_items


raw = INPUT.read_text(encoding='utf-8')
body, nav_items = render_blocks(raw.splitlines())

nav_html = [
    '<nav class="section-nav" aria-label="Report sections">',
    '<div class="section-nav-title">Sections</div>',
    '<div class="section-nav-links">',
    *[f'<a href="#{anchor}">{escape(title)}</a>' for title, anchor in nav_items],
    '</div>',
    '</nav>',
]

html = [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>Mission Control Unified Report</title>',
    '<style>',
    'body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#09111f;color:#e6eefb;line-height:1.55;}',
    '.page{max-width:1180px;margin:0 auto;padding:24px;}',
    '.section-nav{position:sticky;top:0;z-index:20;background:rgba(9,17,31,.92);backdrop-filter:blur(8px);border-bottom:1px solid #243356;padding:12px 24px;}',
    '.section-nav-title{font-size:.8rem;color:#9fe870;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;}',
    '.section-nav-links{display:flex;gap:12px;flex-wrap:wrap;}',
    '.section-nav-links a{font-size:.85rem;padding:4px 8px;border:1px solid #243356;border-radius:999px;background:#101a34;}',
    '.section-nav-links a.active{border-color:#9fe870;color:#9fe870;box-shadow:0 0 0 1px rgba(159,232,112,.2);}',
    'h1,h2,h3{margin:0 0 12px;line-height:1.25;}',
    'h1{color:#9fe870;font-size:2rem;}',
    'h2{color:#7cc7ff;font-size:1.35rem;margin-top:24px;}',
    'h3{color:#f5c56c;font-size:1.05rem;margin-top:18px;}',
    'p,li{font-size:1rem;margin:8px 0;}',
    'ul{margin:8px 0 12px 20px;padding:0;}',
    'hr{border:none;border-top:1px solid #243356;margin:20px 0;}',
    'pre{white-space:pre-wrap;background:#0b1224;border:1px solid #22304f;padding:12px;border-radius:10px;overflow:auto;}',
    '.page > h1:first-child,.page > h2,.page > h3,.page > p,.page > ul,.page > hr,.page > .table-wrap{background:#101a34;border:1px solid #243356;border-radius:16px;padding:18px 22px;box-shadow:0 10px 30px rgba(0,0,0,.22);}',
    '.page > h2,.page > h3{padding-bottom:14px;}',
    '.page > p + p,.page > ul + p,.page > .table-wrap + p{margin-top:18px;}',
    '.table-wrap{overflow:auto;}',
    'table{width:100%;border-collapse:collapse;font-size:.95rem;}',
    'th,td{padding:10px 12px;border-bottom:1px solid #243356;text-align:left;vertical-align:top;}',
    'th{color:#8dd7ff;background:#0b1224;position:sticky;top:0;}',
    'tr:nth-child(even) td{background:rgba(11,18,36,.45);}',
    'a{color:#8dd7ff;text-decoration:none;}',
    'a:hover{text-decoration:underline;}',
    '.scenario-link{font-weight:600;}',
    '.dashboard-backlink{margin-left:10px;font-size:.75rem;font-weight:400;color:#9fe870;}',
    'strong{color:#ffffff;}',
    'em{color:#b6c8e6;}',
    '@media (max-width: 760px){.page{padding:14px;}th,td{padding:8px 9px;font-size:.88rem;}}',
    '</style>',
    '</head>',
    '<body>',
    *nav_html,
    '<div class="page">',
    *body,
    '</div>',
    '<script>',
    'const navLinks=[...document.querySelectorAll(".section-nav-links a")];',
    'const sections=navLinks.map((link)=>document.querySelector(link.getAttribute("href"))).filter(Boolean);',
    'const observer=new IntersectionObserver((entries)=>{entries.forEach((entry)=>{if(!entry.isIntersecting)return;const id=entry.target.id;navLinks.forEach((link)=>link.classList.toggle("active",link.getAttribute("href")==="#"+id));});},{rootMargin:"-35% 0px -55% 0px",threshold:[0,1]});',
    'sections.forEach((section)=>observer.observe(section));',
    'if(navLinks.length){navLinks[0].classList.add("active");}',
    '</script>',
    '</body>',
    '</html>',
]

OUTPUT.write_text('\n'.join(html), encoding='utf-8')
print(f'Wrote {OUTPUT}')
