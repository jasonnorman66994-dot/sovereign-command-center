from pathlib import Path
from html import escape
import re

INPUT = Path('mission_control_presentation.md')
OUTPUT = Path('mission_control_presentation.html')

raw = INPUT.read_text(encoding='utf-8')
parts = [part.strip() for part in raw.split('\n---\n') if part.strip()]
slides = []
for part in parts:
    lines = part.splitlines()
    if lines and lines[0].startswith('marp:'):
        continue
    slides.append(lines)


def render_line(line):
    if not line.strip():
        return '<div class="spacer"></div>'
    if line.startswith('# '):
        return f'<h1>{escape(line[2:])}</h1>'
    if line.startswith('## '):
        return f'<h2>{escape(line[3:])}</h2>'
    if line.startswith('- '):
        return f'<li>{escape(line[2:])}</li>'
    if line.startswith('|'):
        return f'<pre class="table">{escape(line)}</pre>'
    return f'<p>{escape(line)}</p>'

html = [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>Mission Control SOC Brief</title>',
    '<style>',
    'body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0b1020;color:#ecf3ff;}',
    '.deck{display:flex;flex-direction:column;gap:24px;padding:24px;}',
    '.slide{background:linear-gradient(180deg,#101a34,#0d1327);border:1px solid #243356;border-radius:18px;padding:28px;box-shadow:0 10px 30px rgba(0,0,0,.25);}',
    'h1{margin:0 0 16px;font-size:2rem;color:#9fe870;}',
    'h2{margin:0 0 14px;font-size:1.4rem;color:#7cc7ff;}',
    'p,li{font-size:1rem;line-height:1.5;margin:8px 0;}',
    'ul{margin:8px 0 0 20px;}',
    '.table{white-space:pre-wrap;background:#0a0f1d;border:1px solid #1f2b47;padding:10px;border-radius:10px;overflow:auto;}',
    '.spacer{height:8px;}',
    '</style>',
    '</head>',
    '<body>',
    '<div class="deck">',
]

for slide in slides:
    html.append('<section class="slide">')
    in_list = False
    for line in slide:
        if line.startswith('- '):
            if not in_list:
                html.append('<ul>')
                in_list = True
            html.append(render_line(line))
        else:
            if in_list:
                html.append('</ul>')
                in_list = False
            html.append(render_line(line))
    if in_list:
        html.append('</ul>')
    html.append('</section>')

html.extend(['</div>', '</body>', '</html>'])
OUTPUT.write_text('\n'.join(html), encoding='utf-8')
print(f'Wrote {OUTPUT}')
