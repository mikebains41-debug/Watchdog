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

Per held-out day:

| test day | n | threat | quiet | TPR | FPR | gray-alert |
|---|---|---|---|---|---|---|
| 2023-06-16 | 7898 | 2829 | 3215 | 54.1% | 4.04% | 8.7% |
| 2023-06-17 | 8616 | 2798 | 3957 | 27.6% | 0.25% | 1.5% |
| 2023-06-18 | 8616 | 2739 | 3747 | 44.1% | 2.43% | 5.9% |
| 2023-06-19 | 8616 | 2593 | 4129 | 18.9% | 0.46% | 0.4% |
| 2023-06-20 | 8616 | 3144 | 3260 | 25.6% | 0.25% | 0.8% |
| 2023-06-21 | 7577 | 2035 | 4079 | 23.7% | 0.22% | 0.2% |
| 2023-06-22 | 2464 | 976 | 882 | 38.2% | 0.34% | 1.3% |
| 2023-06-23 | 8616 | 2934 | 3152 | 31.8% | 0.10% | 0.3% |
| 2023-06-24 | 8616 | 3012 | 3433 | 36.6% | 0.64% | 1.3% |
| 2023-06-25 | 5136 | 1190 | 2986 | 38.8% | 0.60% | 1.1% |

The pooled false-positive rate met the 1% target, but two individual days did
not: 16 June (4.04%) and 18 June (2.43%). Day-to-day FPR varies; the target holds
on average, not on every day.

Honest reading: at a 1% false-alarm rate the detector catches about a third of
close vessel passages from cable vibration alone, on days it never trained on,
consistently across all ten. It detects a vessel's acoustic/vibration signature,
so a slow or quiet vessel can pass unseen; two-thirds of passages are missed at
this sensitivity. One cable, one area, ten days in June. The method is a simple
energy-baseline detector chosen for licence cleanliness; a stronger model is the
next step and is not claimed here.
