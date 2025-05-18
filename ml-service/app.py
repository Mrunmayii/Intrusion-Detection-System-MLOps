from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
import uvicorn
import joblib
import numpy as np 

app = FastAPI()
model = joblib.load("model_isolation_forest.joblib")

class Features(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: int  # 1 = TCP, 0 = other
    length: int
    timestamp: str

@app.post("/detect")
def detect(features: Features):
    x = np.array([[features.protocol, features.length]])
    # IsolationForest.predict returns 1 for normal, -1 for anomaly
    pred = model.predict(x)[0]
    anomaly = bool(pred == -1)
    return {
        "anomaly": anomaly,
        "reasons": ["Detected by Isolation Forest model"] if anomaly else ["Looks normal"]
    }


@app.post("/detect_batch")
def detect_batch(batch: List[Features]):  # Expecting a raw list of packet dicts
    print("recieved in ml service", len(batch))
    x = np.array([[pkt.protocol, pkt.length] for pkt in batch])
    preds = model.predict(x)
    
    results = []
    for pkt, pred in zip(batch, preds):
        anomaly = bool(pred == -1)
        results.append({
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "anomaly": anomaly,
            "reasons": ["Detected by Isolation Forest model"] if anomaly else ["Looks normal"]
        })
    return {"results": results}

@app.get("/")
def root():
    return {"status": "ml service running"}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=5003)
