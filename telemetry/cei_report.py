# Author: Manmohan (Mike) Bains -- Watchdog AIDR
import statistics


class CEIDistribution:
    def __init__(self, runs):
        if len(runs) < 2:
            raise ValueError(
                "CEIDistribution requires at least 2 runs. A single run "
                "must not be reported as a constant given the documented "
                "~20% coefficient of variation."
            )
        self.runs = list(runs)

    @property
    def median(self):
        return statistics.median(self.runs)

    @property
    def mean(self):
        return statistics.mean(self.runs)

    @property
    def stdev(self):
        return statistics.stdev(self.runs)

    @property
    def cv(self):
        m = self.mean
        if m == 0:
            return None
        return self.stdev / m

    def report(self):
        return {
            'n_runs': len(self.runs),
            'median': round(self.median, 3),
            'mean': round(self.mean, 3),
            'stdev': round(self.stdev, 3),
            'cv': round(self.cv, 4) if self.cv is not None else None,
            'min': round(min(self.runs), 3),
            'max': round(max(self.runs), 3),
        }

    def reliable(self, cv_threshold=0.10):
        c = self.cv
        return c is not None and c <= cv_threshold


def precision_ratio(distribution_a, distribution_b):
    if distribution_a.median == 0 or distribution_b.median == 0:
        raise ValueError("Cannot compute a ratio against a zero median.")
    return distribution_a.median / distribution_b.median
