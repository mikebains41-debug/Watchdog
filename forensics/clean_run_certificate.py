# Author: Manmohan (Mike) Bains -- Watchdog
"""
forensics/clean_run_certificate.py

Generates a structured "clean run" record when a detection session
completes a sustained window with zero alerts across all active
engines.

THIS IS NOT TEE ATTESTATION. Stated as plainly as possible, up front,
because the name "certificate" invites exactly that confusion:

Real hardware TEE attestation (Intel TDX, AMD SEV-SNP) cryptographically
binds a measurement to the actual silicon, verifiable independently
against the hardware vendor's own root of trust -- outside any
software running on the machine itself, including this one. Serial
Alice's real certificates elsewhere in this project do exactly that,
on real TDX-capable hardware via Phala Cloud's dstack SDK. Nothing in
this file runs inside a TEE. Nothing here can prove code integrity
against a host that's already compromised -- if an attacker controls
the machine, they control this class too, and can make it print
whatever it wants. Termux/Android and standard rented GPU containers
do not expose TEE hardware to Watchdog today; closing this gap for
real requires running on TDX-capable rented infrastructure, which
Watchdog has never done, per every honestly-stated Limitations section
elsewhere in this project.

What this DOES provide, and it's real: a hash-chained (via
AuditLedger, so tampering with a past certificate is still detectable
after the fact), structured record of exactly which engines were
active and that a defined window of samples produced zero alerts
across all of them. That's a genuinely useful, weaker claim than
hardware attestation -- a real precursor to that goal, not a stand-in
for it. Do not present this to any external party as TEE attestation.
"""
import time


class CleanRunCertificate:
    def __init__(self, ledger, engine_names, clean_window_samples=3600):
        self.ledger = ledger
        self.engine_names = sorted(engine_names)
        self.clean_window_samples = clean_window_samples
        self.samples_since_last_alert = 0
        self.total_samples = 0
        self.window_start_ts = None
        self.certificates_issued = 0

    def record_sample(self, had_alert, timestamp=None):
        now = timestamp if timestamp is not None else time.time()
        if self.window_start_ts is None:
            self.window_start_ts = now
        self.total_samples += 1

        if had_alert:
            self.samples_since_last_alert = 0
            self.window_start_ts = now
            return None

        self.samples_since_last_alert += 1
        if self.samples_since_last_alert >= self.clean_window_samples:
            return self._issue_certificate(now)
        return None

    def _issue_certificate(self, now):
        cert = {
            'certificate_type': 'CLEAN_RUN_SOFTWARE_ONLY',
            'NOT_TEE_ATTESTED': True,
            'note': ('Software-only record, hash-chained via AuditLedger. '
                     'NOT hardware TEE attestation -- see this module\'s '
                     'docstring for the real, weaker guarantee this '
                     'provides.'),
            'engines_checked': self.engine_names,
            'engine_count': len(self.engine_names),
            'consecutive_clean_samples': self.samples_since_last_alert,
            'window_start': self.window_start_ts,
            'window_end': now,
            'issued_at': now,
        }
        ledger_hash = self.ledger.append('CLEAN_RUN_CERTIFICATE', cert)
        cert['ledger_entry_hash'] = ledger_hash
        self.certificates_issued += 1
        self.samples_since_last_alert = 0
        return cert

    def get_stats(self):
        return {
            'total_samples_seen': self.total_samples,
            'current_clean_streak': self.samples_since_last_alert,
            'clean_window_target': self.clean_window_samples,
            'certificates_issued': self.certificates_issued,
        }
