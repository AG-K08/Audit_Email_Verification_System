# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: show_eml.py
Назначение: Просмотр заголовков и текстовой структуры почтовых сообщений.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import sys
import email
import email.policy
from pathlib import Path

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BASE = Path(__file__).resolve().parents[1]
EML_ROOTS = [BASE / "06_Audit_Tests_and_Samples", BASE / "Email", BASE / "Emails", BASE / "Lab" / "Cases"]
MAX_BODY = 3000


def parse_eml(path: Path) -> dict | None:
    try:
        with open(path, "rb") as fh:
            msg = email.message_from_binary_file(fh, policy=email.policy.default)
    except Exception:
        try:
            with open(path, "rb") as fh:
                msg = email.message_from_binary_file(fh)
        except Exception:
            return None

    bodies, attach = [], []
    try:
        parts = list(msg.walk())
    except Exception:
        parts = []
    for part in parts:
        fn = part.get_filename()
        if fn:
            attach.append(str(fn))
        if part.get_content_maintype() == "multipart":
            continue
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            payload = part.get_payload(decode=True) or b""
            bodies.append(payload.decode("utf-8", errors="replace"))

    hdr_lines = []
    for key in ("From", "To", "Subject", "Date", "Return-Path", "Authentication-Results"):
        val = msg.get(key)
        if val:
            hdr_lines.append(f"{key}: {val}")

    return {
        "file": str(path),
        "subject": str(msg.get("Subject") or ""),
        "from": str(msg.get("From") or ""),
        "to": str(msg.get("To") or ""),
        "date": str(msg.get("Date") or ""),
        "headers": "\n".join(hdr_lines)[:2000],
        "body": "\n".join(bodies),
        "attachments": "; ".join(attach),
    }


def main() -> int:
    if len(sys.argv) < 2:
        print("Использование: python show_eml.py <output_file> [фильтр_по_имени...]")
        return 1
    out = Path(sys.argv[1])
    pats = [p.lower() for p in sys.argv[2:]]
    files = []
    for root in EML_ROOTS:
        if root.exists():
            files.extend(sorted(root.rglob("*.eml")))
    picked = [f for f in files if not pats or any(p in f.name.lower() for p in pats)]
    lines = [f"Попаданий: {len(picked)}", ""]
    for f in picked:
        rec = parse_eml(f)
        if not rec:
            continue
        body = rec["body"]
        lines += [
            "=" * 100,
            f"FILE : {rec['file']}",
            f"DATE : {rec['date']}",
            f"FROM : {rec['from']}",
            f"TO   : {rec['to']}",
            f"SUBJ : {rec['subject']}",
            f"ATTAC: {rec['attachments'] or 'нет'}",
            "-" * 100,
            rec["headers"][:1500],
            "-" * 100,
            body[:MAX_BODY] + ("…[обрезано]" if len(body) > MAX_BODY else ""),
            "",
        ]
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"OK -> {out} ({len(picked)} писем)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
