import pandas as pd
import matplotlib.pyplot as plt
import os

df = pd.read_csv("mem_combo_log.csv")
df = df.dropna(subset=["cgroup_current_bytes"])

# Converti a MB
df["rss_mb"] = df["rss_kb"] / 1024
df["cgroup_current_mb"] = df["cgroup_current_bytes"] / (1024*1024)
df["cgroup_peak_mb"] = df["cgroup_peak_bytes"] / (1024*1024)

# Crea cartella output
os.makedirs("plots", exist_ok=True)

# Plot separato per ogni algo

    # Tempo relativo
t0 = group["timestamp"].iloc[0]
group["t"] = group["timestamp"] - t0

plt.figure(figsize=(12,6))
plt.plot(group["t"], group["cgroup_current_mb"], label="cgroup current (MB)")
plt.plot(group["t"], group["rss_mb"], label="RSS processo (MB)")
plt.plot(group["t"], group["cgroup_peak_mb"], "--", label="cgroup peak (MB)")

plt.title(f"Memoria per algoritmo: {algo}")
plt.xlabel("Tempo (s)")
plt.ylabel("Memoria (MB)")

plt.grid(True, alpha=0.3)
plt.legend()

plt.tight_layout()
plt.savefig(f"plots/bbs.png")
plt.close()

print("Plot generati nella cartella 'plots/'")