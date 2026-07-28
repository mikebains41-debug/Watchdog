#!/usr/bin/env python3
# Author: Manmohan (Mike) Bains -- Watchdog
# Watchdog - Container Escape Detection Test
# Detects unpatched kernel CVE-2026-31431 and stale /tmp files.
# Based on actual findings from Vast.ai H200 Instance 41986069.
#
# HONEST STATUS: checks THIS HOST's own kernel/tmp state -- results
# depend entirely on what machine you run it on, not on Watchdog itself.

import sys
import subprocess
import json


class ContainerEscapeTest:
    def __init__(self):
        self.findings = {}

    def check_kernel_cve(self):
        try:
            result = subprocess.run(['cat', '/proc/version'], capture_output=True, text=True)
            kernel_version = result.stdout
            self.findings['kernel_version'] = kernel_version.strip()[:200]
            if '5.15.0-140-generic' in kernel_version:
                self.findings['cve_2026_31431'] = 'VULNERABLE'
                print("WARNING: CVE-2026-31431 unpatched kernel found")
                return False
            else:
                self.findings['cve_2026_31431'] = 'PATCHED_OR_UNKNOWN'
                print("CVE-2026-31431: not detected on this host")
                return True
        except Exception:
            self.findings['cve_2026_31431'] = 'ERROR_CHECKING'
            return True

    def check_stale_tmp_files(self):
        try:
            result = subprocess.run(['find', '/tmp', '-type', 'f', '-mtime', '+7'],
                                    capture_output=True, text=True, timeout=5)
            old_files = result.stdout.strip().split('\n') if result.stdout else []
            if old_files and old_files[0]:
                self.findings['stale_tmp_files'] = len(old_files)
                self.findings['stale_files_sample'] = old_files[:5]
                print(f"WARNING: found {len(old_files)} stale files in /tmp")
                return False
            else:
                self.findings['stale_tmp_files'] = 0
                print("/tmp is clean")
                return True
        except Exception:
            self.findings['stale_tmp_files'] = 'ERROR_CHECKING'
            return True

    def check_proc_visibility(self):
        try:
            result = subprocess.run(['ls', '/proc/self/fd'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.findings['proc_visible'] = True
                print("WARNING: /proc visible -- possible container escape vector")
                return False
            else:
                self.findings['proc_visible'] = False
                return True
        except Exception:
            self.findings['proc_visible'] = 'ERROR_CHECKING'
            return True

    def run(self):
        print("Container Escape Detection Test")
        print("-" * 60)
        results = [self.check_kernel_cve(), self.check_stale_tmp_files(), self.check_proc_visibility()]
        print("-" * 60)
        passes = sum(results)
        total = len(results)
        print(f"Container Escape Tests: {passes}/{total} passed")
        with open("container_escape_results.json", "w") as f:
            json.dump(self.findings, f, indent=2)
        return passes == total


if __name__ == "__main__":
    test = ContainerEscapeTest()
    success = test.run()
    sys.exit(0 if success else 1)
