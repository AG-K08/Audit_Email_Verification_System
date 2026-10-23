# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: grep_eml.py
Назначение: Быстрый поиск токенов и индикаторов компрометации в сырых байтах EML.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import sys
from pathlib import Path

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BASE = Path(__file__).resolve().parents[1]
ROOTS = [BASE / "06_Audit_Tests_and_Samples", BASE / "Email", BASE / "Emails"]


def main() -> int:
    if len(sys.argv) < 3:
        print("Использование: python grep_eml.py <output_file> <token1> [token2...]")
        return 1
    out = Path(sys.argv[1])
    out.parent.mkdir(parents=True, exist_ok=True)
    tokens = [t.lower().encode("utf-8", "ignore") for t in sys.argv[2:]]

    hits = {}
    files = []
    for root in ROOTS:
        if root.exists():
            files.extend(sorted(root.rglob("*.eml")))
    for n, f in enumerate(files, 1):
        try:
            raw = f.read_bytes().lower()
        except Exception:
            continue
        found = [t.decode("utf-8", "ignore") for t in tokens if t in raw]
        if found:
            hits[str(f)] = found
        if n % 3000 == 0:
            print(f"  ...{n}/{len(files)}, совпадений: {len(hits)}", flush=True)

    token_strs = [t.decode("utf-8", "ignore") for t in tokens]
    lines = [f"Проверено писем: {len(files)}", f"Писем с токенами {token_strs}: {len(hits)}", ""]
    for path, found in sorted(hits.items()):
        lines.append(f"{path}  ::  {', '.join(sorted(set(found)))}")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"OK -> {out} (писем с совпадениями: {len(hits)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
