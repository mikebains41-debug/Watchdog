"""
save_physics_90_91_output.py

Module90/91's test script (test_physics_90_91.py) only prints to the
terminal — nothing gets saved to disk, so that run's output is lost the
moment the terminal scrolls away or the session ends.

This wrapper runs your REAL test_physics_90_91.py as a subprocess,
captures its actual stdout verbatim, and saves it to a JSON file —
both the full raw text (so nothing is lost or reconstructed from
memory) and a parsed set of the key numeric values for quick reference.

This does NOT reimplement or guess at module90/91's logic — it captures
exactly what your real, already-fixed code actually printed, guaranteed
authentic because it's the live output of the real run, not something
rebuilt from a description of it.
"""
import subprocess
import json
import datetime
import os
import re

TEST_SCRIPT = "test_physics_90_91.py"


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run_and_capture():
    try:
        proc = subprocess.run(
            ["python3", TEST_SCRIPT],
            capture_output=True, text=True, timeout=60
        )
        raw_stdout = proc.stdout
        raw_stderr = proc.stderr
        exit_code = proc.returncode
    except FileNotFoundError:
        print(f"Could not find {TEST_SCRIPT} in the current directory. "
              f"Run this from the same folder as test_physics_90_91.py "
              f"(the main Watchdog/ folder).")
        return None
    except subprocess.TimeoutExpired:
        print(f"{TEST_SCRIPT} did not finish within 60s.")
        return None

    if exit_code != 0:
        print(f"WARNING: {TEST_SCRIPT} exited with code {exit_code}")
        print("stderr:")
        print(raw_stderr)

    print(raw_stdout)

    def find(pattern, text=raw_stdout, cast=float):
        m = re.search(pattern, text)
        if not m:
            return None
        try:
            return cast(m.group(1))
        except (ValueError, TypeError):
            return m.group(1)

    parsed = {
        "module90": {
            "loss_tangent_material_term": find(
                r"Loss tangent material term:\s*([\d.eE+-]+)"),
            "predicted_t1_us": find(
                r"Predicted T1:\s*([\d.eE+-]+)\s*us"),
            "effective_loss_tangent": find(
                r"Effective loss tangent:\s*([\d.eE+-]+)"),
            "thermal_saturation_factor": find(
                r"Thermal saturation factor:\s*([\d.eE+-]+)"),
            "calibration_status": find(
                r"Calibration status:\s*(.+)", cast=str),
            "measured_t1_example_us": find(
                r"Measured \(example\):\s*([\d.eE+-]+)\s*us"),
            "ratio_predicted_to_measured": find(
                r"Ratio:\s*([\d.eE+-]+)"),
        },
        "module91": {
            "psd_at_1hz_phi0_sq_per_hz": find(
                r"PSD at 1 Hz:\s*([\d.eE+-]+)"),
            "psd_at_1khz_phi0_sq_per_hz": find(
                r"PSD at 1 kHz:\s*([\d.eE+-]+)"),
            "t2star_away_from_sweet_spot_us": find(
                r"Predicted T2\*:\s*([\d.eE+-]+)\s*us"),
            "t2star_at_sweet_spot": find(
                r"Predicted T2\*:\s*(inf)", cast=str),
            "anomaly_detection_normal_series_flagged_consistent": find(
                r"Series: \[.*?\]\s*\nConsistent with 1/f drift:\s*(True|False)",
                cast=str),
            "anomaly_detection_injected_step_flagged_consistent": find(
                r"Series with injected step: \[.*?\]\s*\nConsistent with 1/f drift:\s*(True|False)",
                cast=str),
        },
    }

    result = {
        "test_script": TEST_SCRIPT,
        "exit_code": exit_code,
        "raw_stdout": raw_stdout,
        "raw_stderr": raw_stderr if raw_stderr else None,
        "parsed_values": parsed,
        "note": ("raw_stdout is the exact, unmodified terminal output of "
                  "test_physics_90_91.py — this is the authoritative "
                  "record. parsed_values is a best-effort regex "
                  "extraction for convenience; if a value shows null "
                  "there, check raw_stdout directly rather than trusting "
                  "the parse."),
        "timestamp": now_iso(),
    }

    return result


if __name__ == "__main__":
    result = run_and_capture()
    if result is None:
        exit(1)

    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "module90_91_physics_result.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {output_path}")
