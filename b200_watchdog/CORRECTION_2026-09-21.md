# Correction note for the B200 summaries in this folder

The B200_SUMMARY_*.txt files here are the original run records from July 2026
and are deliberately left unedited.

Their alert counts are detector fires on deliberately induced workloads. A fire
shows the detector's condition was met by that workload -- not that the detector
correctly identified the attack or failure it is named after. Known from later
testing (2026-09-21):

- PACKAGE_CRACK_PREDICTED: the detector then fired on any >8 C temperature change
  across busy samples in 100 s -- every warm-up. Not evidence of solder fatigue.
  Redesigned as THERMAL_CYCLING_EXPOSURE (INFO), commit a8978b6.
- CAPACITOR_AGING_PREDICTED: flags power ripple under load; the induced workloads
  varied power deliberately, so a fire shows workload ripple, not capacitor ageing.
- GHOST_POWER_PREDICTED: fires on ordinary busy-to-idle transitions with a model
  loaded; now IDLE_RESIDENT_ENERGY (INFO) on loaded GPUs, commit 7abc65b.

Measurements in these runs (contention loss, idle power at 0% utilisation, VRAM
recovery attempts) are unaffected by this note.
