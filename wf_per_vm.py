import sys, json, numpy as np
sys.path.insert(0, "scripts")
from analyze_wf import features, SEED
from multiprocessing import Pool
from pathlib import Path
def main():
    from sklearn.ensemble import RandomForestClassifier
    src = Path("data/wf")
    recs = [json.loads(l) for f in sorted(src.glob("vm*/visits*.jsonl")) for l in open(f)]
    recs = [r for r in recs if r["status"] == "ok" and not r["label"].startswith("unmon_")]
    paths = [src/f"vm{r['vm']}"/f"{r['label']}__vm{r['vm']}_i{r['i']:04d}.pcap" for r in recs]
    with Pool() as p: F = p.map(features, paths, chunksize=8)
    X = np.nan_to_num(np.array([f[0] for f in F], float)); y = np.array([r["label"] for r in recs]); vm = np.array([r["vm"] for r in recs])
    for v in range(1, 6):
        m = RandomForestClassifier(500, n_jobs=-1, random_state=SEED).fit(X[vm != v], y[vm != v])
        print(f"vm{v}: test acc {(m.predict(X[vm == v]) == y[vm == v]).mean():.3f}, "
              f"середня тривалість {np.median(X[vm == v][:, 7]):.1f} с, медіана пакетів {np.median(X[vm == v][:, 0]):.0f}")
    
if __name__ == '__main__':
    main()