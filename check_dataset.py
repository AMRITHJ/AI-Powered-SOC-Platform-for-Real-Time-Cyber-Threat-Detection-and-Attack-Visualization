import pandas as pd
from backend.config import NF_UQ_PATH

print("Loading dataset sample...")
df = pd.read_csv(NF_UQ_PATH, nrows=500000, low_memory=False)

print()
print("PORT_SCAN rows - key feature averages:")
ps = df[df["Attack"] == "PortScan"]
print(f"  Total PORT_SCAN rows: {len(ps):,}")
print(f"  L4_DST_PORT mean:   {ps["L4_DST_PORT"].mean():.0f}")
print(f"  IN_BYTES mean:      {ps["IN_BYTES"].mean():.0f}")
print(f"  IN_PKTS mean:       {ps["IN_PKTS"].mean():.1f}")
print(f"  TCP_FLAGS mean:     {ps["TCP_FLAGS"].mean():.1f}")
print(f"  FLOW_DURATION mean: {ps["FLOW_DURATION_MILLISECONDS"].mean():.0f}ms")

print()
print("BENIGN rows - key feature averages:")
bn = df[df["Attack"] == "Benign"]
print(f"  Total BENIGN rows: {len(bn):,}")
print(f"  L4_DST_PORT mean:   {bn["L4_DST_PORT"].mean():.0f}")
print(f"  IN_BYTES mean:      {bn["IN_BYTES"].mean():.0f}")
print(f"  IN_PKTS mean:       {bn["IN_PKTS"].mean():.1f}")
print(f"  TCP_FLAGS mean:     {bn["TCP_FLAGS"].mean():.1f}")
print(f"  FLOW_DURATION mean: {bn["FLOW_DURATION_MILLISECONDS"].mean():.0f}ms")

print()
print("DDOS rows - key feature averages:")
dd = df[df["Attack"] == "DDoS"]
print(f"  Total DDOS rows: {len(dd):,}")
print(f"  IN_BYTES mean:      {dd["IN_BYTES"].mean():.0f}")
print(f"  IN_PKTS mean:       {dd["IN_PKTS"].mean():.1f}")
print(f"  TCP_FLAGS mean:     {dd["TCP_FLAGS"].mean():.1f}")
print(f"  FLOW_DURATION mean: {dd["FLOW_DURATION_MILLISECONDS"].mean():.0f}ms")
