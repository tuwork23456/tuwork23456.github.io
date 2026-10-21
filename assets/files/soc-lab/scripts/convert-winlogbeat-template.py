#!/usr/bin/env python3
"""Convert exported Winlogbeat 9.5.5 template to SOC daily-index template."""
import json
from pathlib import Path

src = Path('/home/socem01/winlogbeat.template.json')
dst = Path('/home/socem01/winlogbeat-soc.template.json')
t = json.loads(src.read_text(encoding='utf-8-sig'))
t['index_patterns'] = ['winlogbeat-*']
t.pop('data_stream', None)
t['priority'] = 250
dst.write_text(json.dumps(t, ensure_ascii=False, indent=2), encoding='utf-8')
print(dst)
