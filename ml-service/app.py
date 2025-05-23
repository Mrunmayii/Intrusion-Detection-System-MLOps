from fastapi import FastAPI, Response
from pydantic import BaseModel
from typing import List
import uvicorn
import joblib
import numpy as np 
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

app = FastAPI()
model = joblib.load("model_isolation_forest.joblib")

DETECT_REQUESTS = Counter("ml_detect_requests_total", "Total detect requests")
DETECT_BATCH_REQUESTS = Counter("ml_detect_batch_requests_total", "Total detect_batch requests")
ANOMALIES_DETECTED = Counter("ml_anomalies_detected_total", "Total anomalies detected")

class Features(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: int 
    length: int
    timestamp: str

@app.post("/detect")
def detect(features: Features):
    DETECT_REQUESTS.inc()

    x = np.array([[features.protocol, features.length]])
    # IsolationForest.predict returns 1 for normal, -1 for anomaly
    pred = model.predict(x)[0]
    anomaly = bool(pred == -1)
    print(anomaly)
    if anomaly:
        ANOMALIES_DETECTED.inc()
    return {
        "anomaly": anomaly,
        "reasons": ["Detected by Isolation Forest model"] if anomaly else ["Looks normal"]
    }


@app.post("/detect_batch")
def detect_batch(batch: List[Features]):  # Expecting a raw list of packet dicts
    DETECT_BATCH_REQUESTS.inc()

    print("recieved in ml service", len(batch))
    x = np.array([[pkt.protocol, pkt.length] for pkt in batch])
    preds = model.predict(x)
    print("prediction", preds)
    results = []
    for pkt, pred in zip(batch, preds):
        anomaly = bool(pred == -1)
        if anomaly:
            ANOMALIES_DETECTED.inc()
        results.append({
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "anomaly": anomaly,
            "reasons": ["Detected by Isolation Forest model"] if anomaly else ["Looks normal"]
        })
        print("is anomaly", anomaly)
    return {"results": results}

@app.get("/metrics")
def metrics():
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)

@app.get("/")
def root():
    return {"status": "ml service running"}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=5003)
