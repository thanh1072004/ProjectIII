#!/usr/bin/env python3
"""
Convert the ECML/PKDD 2007 dataset (text format) -> Apache combined log
format compatible with this IDS, mirroring the conventions of
convert_csic_full.py:

  - POST/PUT body is folded into the URL as ...?POST_BODY=<url-encoded body>
  - attack requests get "(Simulated-Attack)" appended to the User-Agent
    (this is the label marker the evaluation pipeline keys off)
  - status fixed at 200, random size, synthetic timestamp/IP

Input  (in datasets/ecml/, as downloaded):
    xml_train.txt   24,504 requests, all class=Valid           -> CLEAN ONLY
    xml_test.txt    25,612 requests, 10,502 Valid + 15,110 atk  -> LABELLED EVAL

ECML block format:
    Start - Id: <id>
    class: <Valid|XSS|SqlInjection|LdapInjection|XPathInjection|
            PathTransversal|OsCommanding|SSI>
    <METHOD URL HTTP/x.x>
    <Header: value> ...
    ----: ------
    ~~~~~: ~~~~~~
    <blank>
    <body OR "null">
    End - Id: <id>

Outputs (written into datasets/ecml/):
    ecml_train_clean.log   (Tier-3 one-class / supervised normal samples)
    ecml_test.log          (labelled evaluation set)
"""
import os, sys, io, re, random
import urllib.parse
from datetime import datetime, timedelta

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ECML_DIR = os.path.join(PROJECT_ROOT, "datasets", "ecml")

REQ_RE = re.compile(
    r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT|PATCH)\s+(.*)\s+(HTTP/\d\.\d)\s*$')


def parse_block(lines):
    """Parse one ECML request block into (cls, method, url, proto, ua, ref, body)."""
    cls = None
    req_idx = None
    for i, l in enumerate(lines):
        s = l.strip()
        if cls is None and s.lower().startswith("class:"):
            cls = s.split(":", 1)[1].strip()
        if req_idx is None and REQ_RE.match(s):
            req_idx = i
    if cls is None or req_idx is None:
        return None

    m = REQ_RE.match(lines[req_idx].strip())
    method, url, proto = m.group(1), m.group(2).strip(), m.group(3)
    if not url:
        url = "/"

    # Headers: from after request line until the first separator line.
    headers = {}
    tilde_idx = None
    for j in range(req_idx + 1, len(lines)):
        s = lines[j].rstrip("\n")
        if s.startswith("----:") or s.startswith("~~~~~:"):
            if s.startswith("~~~~~:"):
                tilde_idx = j
            # keep scanning to also catch the ~~~~~ line if we hit ---- first
            if tilde_idx is not None:
                break
            continue
        if ":" in s:
            k, v = s.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    if tilde_idx is None:
        for j in range(req_idx + 1, len(lines)):
            if lines[j].startswith("~~~~~:"):
                tilde_idx = j
                break

    # Body: everything after the ~~~~~ line that isn't blank or the literal "null".
    body = None
    if tilde_idx is not None:
        rest = [lines[k].strip() for k in range(tilde_idx + 1, len(lines))]
        body_lines = [r for r in rest if r and r.lower() != "null"]
        if body_lines:
            body = " ".join(body_lines)

    ua = headers.get("user-agent", "-") or "-"
    ref = headers.get("referer", "-") or "-"
    return cls, method, url, proto, ua, ref, body


def convert(in_path, out_path, clean_only=False):
    random.seed(42)
    start_time = datetime(2026, 1, 1, 0, 0, 0)
    n_total = n_attack = n_clean = n_skip = 0

    with open(in_path, "r", encoding="utf-8", errors="replace") as fin, \
         open(out_path, "w", encoding="utf-8") as fout:
        block = None
        for line in fin:
            if line.startswith("Start - Id:"):
                block = []
                continue
            if line.startswith("End - Id:"):
                if block is not None:
                    parsed = parse_block(block)
                    if parsed:
                        cls, method, url, proto, ua, ref, body = parsed
                        is_attack = cls.strip().lower() != "valid"

                        if clean_only and is_attack:
                            block = None
                            continue  # train file is all Valid anyway; guard

                        # Fold POST/PUT body into the URL (POST_BODY convention)
                        if method in ("POST", "PUT") and body:
                            enc = urllib.parse.quote(body)
                            url = url + ("&" if "?" in url else "?") + "POST_BODY=" + enc

                        # Sanitise so the quoted log fields stay parseable
                        url = url.replace('"', "%22").replace(" ", "%20")
                        ua = ua.replace('"', "'")
                        ref = ref.replace('"', "'")

                        if is_attack:
                            ua = ua + " (Simulated-Attack)"
                            n_attack += 1
                        else:
                            n_clean += 1

                        ip = f"{random.randint(10,192)}.{random.randint(0,255)}." \
                             f"{random.randint(0,255)}.{random.randint(1,254)}"
                        dt = start_time.strftime("%d/%b/%Y:%H:%M:%S +0700")
                        start_time += timedelta(seconds=random.randint(1, 5))
                        size = random.randint(500, 5000)

                        fout.write(f'{ip} - - [{dt}] "{method} {url} {proto}" '
                                   f'200 {size} "{ref}" "{ua}"\n')
                        n_total += 1
                    else:
                        n_skip += 1
                block = None
                continue
            if block is not None:
                block.append(line)

    print(f"[OK] {os.path.basename(in_path)} -> {os.path.basename(out_path)}")
    print(f"     written={n_total}  attack={n_attack}  clean={n_clean}  skipped={n_skip}")
    return n_total, n_attack, n_clean


if __name__ == "__main__":
    train_in = os.path.join(ECML_DIR, "xml_train.txt")
    test_in = os.path.join(ECML_DIR, "xml_test.txt")
    for p in (train_in, test_in):
        if not os.path.exists(p):
            print(f"ERROR: not found: {p}")
            sys.exit(1)

    print("Converting ECML/PKDD 2007 -> Apache log format ...\n")
    convert(train_in, os.path.join(ECML_DIR, "ecml_train_clean.log"), clean_only=True)
    convert(test_in, os.path.join(ECML_DIR, "ecml_test.log"), clean_only=False)
    print("\nDone. Files written into datasets/ecml/")
