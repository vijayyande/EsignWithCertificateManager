import json
from graphify.detect import detect
from pathlib import Path

result = detect(Path('.'))
Path('graphify-out/.graphify_detect.json').write_text(
    json.dumps(result, ensure_ascii=False), encoding='utf-8')

files = result.get('files', {})
print(f"total_files={result.get('total_files', 0)}")
print(f"total_words={result.get('total_words', 0)}")
for cat, fl in files.items():
    if fl:
        exts = sorted({Path(f).suffix for f in fl})
        print(f"{cat}: {len(fl)} files ({' '.join(exts[:8])})")
skipped = result.get('skipped_sensitive', [])
if skipped:
    print(f"skipped_sensitive={len(skipped)}")
    for s in skipped:
        print(f"  SKIPPED: {s}")
