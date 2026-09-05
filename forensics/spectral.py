# Author: Manmohan (Mike) Bains -- Watchdog
import csv, os, math, json
from datetime import datetime
def fft(signal):
    n = len(signal)
    if n <= 1: return signal
    if n % 2 != 0: signal = signal[:n-1]; n = n-1
    even = fft(signal[0::2])
    odd = fft(signal[1::2])
    T = [complex(math.cos(-2*math.pi*k/n), math.sin(-2*math.pi*k/n))*odd[k % (n//2)] for k in range(n//2)]
    return [even[k]+T[k] for k in range(n//2)] + [even[k]-T[k] for k in range(n//2)]
class SpectralAnalyzer:
    def __init__(self, sample_hz=100):
        self.sample_hz = sample_hz
    def analyze_csv(self, csv_path, power_col='power_w'):
        if not os.path.exists(csv_path): return None
        signal = []
        with open(csv_path,'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try: signal.append(float(row.get(power_col,0)))
                except (ValueError, TypeError): pass
        if len(signal) < 16: return None
        n = 2**int(math.log2(len(signal)))
        signal = signal[:n]
        mean = sum(signal)/len(signal)
        signal = [s - mean for s in signal]
        spectrum = fft(signal)
        magnitudes = [abs(c) for c in spectrum[:n//2]]
        freq_resolution = self.sample_hz / n
        freqs = [i * freq_resolution for i in range(n//2)]
        top_freqs = sorted(zip(freqs, magnitudes), key=lambda x: -x[1])[:10]
        covert_indicators = [f for f,m in top_freqs if 1 < f < 100 and m > sum(magnitudes)/len(magnitudes)*3]
        result = {
            'file': os.path.basename(csv_path),
            'samples': n,
            'sample_hz': self.sample_hz,
            'freq_resolution_hz': round(freq_resolution, 4),
            'top_frequencies': [{'freq_hz':round(f,3),'magnitude':round(m,2)} for f,m in top_freqs],
            'covert_channel_indicators': [round(f,3) for f in covert_indicators],
            'covert_channel_detected': len(covert_indicators) > 0,
            'timestamp': datetime.now().isoformat()
        }
        if result['covert_channel_detected']:
            print(f"[SPECTRAL] COVERT CHANNEL DETECTED in {os.path.basename(csv_path)}")
            print(f"[SPECTRAL] Carrier frequencies: {result['covert_channel_indicators']} Hz")
        return result
    def analyze_all(self, data_dir='watchdog_data', output_path=None):
        results = []
        for f in os.listdir(data_dir):
            if f.endswith('.csv'):
                r = self.analyze_csv(os.path.join(data_dir,f))
                if r: results.append(r)
        out = output_path or os.path.join(data_dir,'spectral_analysis.json')
        with open(out,'w') as f: json.dump(results, f, indent=2)
        print(f"[SPECTRAL] Analysis complete — {len(results)} files → {out}")
        return results
if __name__ == '__main__':
    SpectralAnalyzer().analyze_all()
