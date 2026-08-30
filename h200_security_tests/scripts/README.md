# H200 Security Tests — CVE 2048350
## Author: Manmohan Mike Bains
## Date: June 2026

## Test Scripts

### T-28 — Timing Attack
Measures ghost power decay curve for 3 workload sizes.
Proves workload size detectable from power decay alone.
Run: bash t28_timing_attack.sh

### T-29 — Power Side Channel
Records power fluctuation signatures at 100Hz during active inference.
Proves batch size and precision detectable from power alone.
Run: bash t29_power_side_channel.sh

### T-30 — Scheduler Oracle
Measures ghost power window timing after workload exit.
Proves attacker can time job submission to maximize VRAM access.
Run: bash t30_scheduler_oracle.sh

### T-31 — VRAM Content Classification
Reads residual bytes after graceful exit.
Calculates entropy and searches for structured data patterns.
Proves residual contains model data not random noise.
Run: bash t31_vram_content.sh

### T-32 — Cross Tenant Simulation
Tenant A loads known values. Tenant B reads after exit.
Proves end-to-end cross-tenant data recovery.
Run: bash t32_cross_tenant.sh

### T-33 — SIGKILL vs Graceful
Side by side comparison of cleanup methods.
Proves SIGKILL clears VRAM. Graceful exit does not.
Run: bash t33_sigkill_vs_graceful.sh

## Raw Data Location
All CSV files saved in test-specific subfolders.
All pushed to private repo automatically after each test.

## CVE Reference
CVE Request 2048350
MITRE Reference MCID15783488
