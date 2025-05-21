import json
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import numpy as np

X = []

def encode_protocol(proto):
    mapping = {
        "TCP": 1,
        "UDP": 2,
        "DNS": 3,
        "ICMP": 4
    }
    return mapping.get(proto.upper(), 0)
    # return 1 if proto == "TCP" else 0

# Load and filter normal packets only for training
with open("packets.jsonl") as f:
    for line in f:
        pkt = json.loads(line)
        if pkt["label"] == "normal":
            features = [
                encode_protocol(pkt["protocol"]),
                pkt["length"],
            ]
            X.append(features)

X = np.array(X)

clf = IsolationForest(contamination=0.05, random_state=42)  # contamination = expected anomaly fraction
clf.fit(X)

joblib.dump(clf, "model_isolation_forest.joblib")

print("Isolation Forest model trained on normal TCP, UDP, DNS, ICMP data.")
