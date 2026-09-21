# DAS vessel-proximity detection — Belgian cable, measured result

2026-09-21. Real result, leave-one-day-out over 10 days.

Data: Marlinks-NS DAS dataset, Ramirez-Torres et al., 2026, CC BY 4.0,
doi:10.5281/zenodo.15611778. Belgian seabed cable, 16–25 June 2023,
74,771 windows. Full file (13.14 GB) verified md5 407ad62bb8eb02f472cda329d0f31750.
Watchdog's own detector code; nothing taken from the dataset authors' GPL-3.0 repo.

Method: per-channel log-energy, per-channel median/MAD quiet baseline, top-K
z-score, threshold set on the training days to a 1% false-positive target,
day-wise k-fold (each day held out, trained on the other nine). Threat <= 1000 m,
quiet > 2000 m, the 1000–2000 m gray zone scored separately and excluded.

POOLED over 10 held-out days:
  detection rate (TPR)  33.6%  (8155 of 24250 threat windows)
  false-positive rate   0.95%  (313 of 32840 quiet windows)
  gray-zone alert rate   2.3%  (398 of 17681)

Per day: TPR 18.9%–54.1%, FPR 0.10%–4.04% (table in marlinks_das_result.json).

Honest reading: at a 1% false-alarm rate the detector catches about a third of
close vessel passages from cable vibration alone, on days it never trained on,
consistently across all ten. It detects a vessel's acoustic/vibration signature,
so a slow or quiet vessel can pass unseen; two-thirds of passages are missed at
this sensitivity. One cable, one area, ten days in June. The method is a simple
energy-baseline detector chosen for licence cleanliness; a stronger model is the
next step and is not claimed here.
