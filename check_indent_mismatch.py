#!/usr/bin/env python3
"""
Checks every file the earlier normalize_authorship.py script modified
(the "Replaced existing line" bucket) for the exact corruption pattern
already confirmed twice: the replacement author line has ZERO leading
whitespace, but landed inside code where surrounding lines are
indented -- a dict, a function body, a decorator stack. That mismatch
is a strong, real signal the replaced line used to be actual code, not
a genuine top-of-file comment.

Run from the repo root: python3 check_indent_mismatch.py
"""
import os

FILES = [
    "detection/cc_integrity_detector.py",
    "detection/ecc_error_trend_detector.py",
    "detection/throughput_contention_detector.py",
    "forensics/attested_report.py",
    "forensics/timeline.py",
    "tests/test_cc_integrity_detector.py",
    "tests/test_ecc_error_trend_detector.py",
    "tests/test_positive_controls_advanced.py",
    "tests/test_positive_controls_hardware.py",
    "tests/test_positive_controls_llm.py",
    "tests/test_positive_controls_memory.py",
    "tests/test_throughput_contention_detector.py",
    "validation_results/contention_benchmark.py",
    "validation_results/cross_gpu_isolation_full_methodology.py",
    "validation_results/cross_gpu_isolation_test.py",
    "validation_results/cross_tenant_vram_full_methodology.py",
    "validation_results/cross_tenant_vram_sigkill_full_methodology.py",
    "validation_results/h200_vram_cert_fixed.py",
    "validation_results/tenant_a_writer.py",
    "validation_results/tenant_a_writer_sigkill.py",
    "validation_results/tenant_b_reader.py",
    "validation_results/watchdog_memory_attacks_validation.py",
    "validation_results/watchdog_validation.py",
    "validation_results/host_isolation_audit.sh",
]


def indent_of(line):
    return len(line) - len(line.lstrip())


def check_file(path):
    if not os.path.exists(path):
        return f"MISSING: {path} not found"

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    findings = []
    for i, line in enumerate(lines):
        if "Watchdog AIDR" in line and ("Author" in line or "Manmohan" in line):
            my_indent = indent_of(line)
            prev_line = lines[i - 1] if i > 0 else ""
            next_line = lines[i + 1] if i + 1 < len(lines) else ""
            prev_indent = indent_of(prev_line) if prev_line.strip() else None
            next_indent = indent_of(next_line) if next_line.strip() else None

            mismatch = False
            if prev_indent is not None and prev_indent != my_indent:
                mismatch = True
            if next_indent is not None and next_indent != my_indent:
                mismatch = True

            findings.append({
                "line_num": i + 1,
                "my_indent": my_indent,
                "prev_indent": prev_indent,
                "next_indent": next_indent,
                "mismatch": mismatch,
                "context": [
                    (i, lines[i - 1].rstrip("\n")) if i > 0 else None,
                    (i + 1, line.rstrip("\n")),
                    (i + 2, lines[i + 1].rstrip("\n")) if i + 1 < len(lines) else None,
                ],
            })
    return findings


def main():
    suspicious = []
    clean = []
    missing = []

    for path in FILES:
        result = check_file(path)
        if isinstance(result, str):
            missing.append(result)
            continue
        if not result:
            clean.append(f"{path}: no author line found at all (unexpected)")
            continue
        any_mismatch = any(f["mismatch"] for f in result)
        if any_mismatch:
            suspicious.append((path, result))
        else:
            clean.append(path)

    print("=" * 70)
    print("INDENTATION MISMATCH CHECK")
    print("=" * 70)
    print(f"Checked: {len(FILES)} files")
    print(f"Clean (indentation matches surroundings): {len(clean)}")
    print(f"SUSPICIOUS (indentation mismatch found):  {len(suspicious)}")
    print(f"Missing/not found: {len(missing)}")

    if suspicious:
        print("\n--- SUSPICIOUS FILES, NEED MANUAL REVIEW ---")
        for path, findings in suspicious:
            print(f"\n{path}:")
            for f in findings:
                if f["mismatch"]:
                    print(f"  Line {f['line_num']}: this_indent={f['my_indent']}, "
                          f"prev_indent={f['prev_indent']}, next_indent={f['next_indent']}")
                    for ctx in f["context"]:
                        if ctx:
                            ln, txt = ctx
                            print(f"    {ln}: {txt}")

    if clean:
        print("\n--- CLEAN (author line indentation matches context) ---")
        for c in clean:
            print(f"  {c}")

    if missing:
        print("\n--- MISSING FILES ---")
        for m in missing:
            print(f"  {m}")


if __name__ == "__main__":
    main()
