from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Optional
import uvicorn
import asyncio
from prometheus_fastapi_instrumentator import Instrumentator

# MODEL_URL = "http://ml-service:5003/detect"
MODEL_URL = "http://ml-service:5003/detect_batch"
# MODEL_URL = "http://localhost:5003/detect_batch"

from fastapi import FastAPI
from pydantic import BaseModel
import asyncio
import httpx

app = FastAPI()
Instrumentator().instrument(app).expose(app)

batch = []
BATCH_SIZE = 50
BATCH_INTERVAL = 5  # seconds
batch_lock = asyncio.Lock()

class Packet(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    timestamp: str

def convert(packet: Packet):
    return {
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "protocol": 1 if packet.protocol == "TCP" else 0,
        "length": packet.length,
        "timestamp": packet.timestamp
    }

@app.post("/extract")
async def extract(packet: Packet):
    async with batch_lock:
        batch.append(convert(packet))
        if len(batch) >= BATCH_SIZE:
            to_send = batch.copy()
            batch.clear()
            asyncio.create_task(send_to_ml_model(to_send))  # fire-and-forget
    return {"status": "packet buffered"}

store_results_for_frontend = []
async def send_to_ml_model(packets):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(MODEL_URL, json=packets)
            print(f"Sent batch of {len(packets)} packets, status: {response.status_code}")
            if response.status_code == 200:
                results = response.json().get("results", [])
                # return results
                combined = []
                for pkt, res in zip(packets, results):
                    combined.append({
                        "src_ip": pkt["src_ip"],
                        "dst_ip": pkt["dst_ip"],
                        "protocol": "TCP" if pkt["protocol"] == 1 else "Other",
                        "length": pkt["length"],
                        "timestamp": pkt["timestamp"],
                        "anomaly": res["anomaly"],
                        "label": "Anomaly" if res["anomaly"] else "Normal",
                        "reasons": res["reasons"]
                    })
                store_results_for_frontend.extend(combined)  # Save for frontend
                print(combined)
                return combined
                # return response.json()
            else:
                print("Model service error:", response.text)
    except Exception as e:
        print("Error sending to ML model:", e)

async def batch_sender():
    while True:
        await asyncio.sleep(BATCH_INTERVAL)
        if batch:
            to_send = batch.copy()
            batch.clear()
            await send_to_ml_model(to_send)

@app.post("/clear_results")
def clear_results():
    store_results_for_frontend.clear()
    return {"status": "cleared"}

@app.get("/results")
def get_results():
    return {"results": store_results_for_frontend}

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(batch_sender())

@app.get("/")
def root():
    return {"status": "preprocessing service running"}

# @app.post("/extract")
# async def extract_features(packet: Packet):
#     print("in preprocess")
#     features = {
#         "src_ip": packet.src_ip,
#         "dst_ip": packet.dst_ip,
#         "protocol": 1 if packet.protocol == "TCP" else 0,
#         "length": packet.length,
#         "timestamp": packet.timestamp,
#     }
#     # print("Extracted features:", features)
#     # return {"status": "received", "features": features}
#     try:
#         response = requests.post(MODEL_URL, json=features)
#         model_response = response.json()
#         return {
#             "features": features,
#             "anomaly": model_response.get("anomaly"),
#             "reasons": model_response.get("reasons", [])
#         }
#     except Exception as e:
#         print("Error contacting anomaly-detector:", e)
#         return {
#             "features": features,
#             "error": str(e),
#             "anomaly": False,
#             "reasons": ["ML model failed"]
#         }
#     return {"status": "received", "features": features}

# @app.post("/extract_batch")
# async def extract_batch(data: dict):
#     print("in preprocess")
#     packets = data.get("packets", [])
#     results = []

#     for pkt in packets:
#         try:
#             features = {
#                 "src_ip": pkt["src_ip"],
#                 "dst_ip": pkt["dst_ip"],
#                 "protocol": 1 if pkt["protocol"] == "TCP" else 0,
#                 "length": pkt["length"],
#                 "timestamp": pkt["timestamp"],
#             }

#             # Optional: change this to batch call if model supports it
#             response = requests.post(MODEL_URL, json=features)
#             model_response = response.json()
#             # print("Anomaly Detection:", model_response)

#             results.append({
#                 "features": features,
#                 "anomaly": model_response.get("anomaly"),
#                 "reasons": model_response.get("reasons", [])
#             })
#         except Exception as e:
#             print("Error processing packet:", e)

#     return {"status": "batch processed", "results": results}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=5002, reload=True)

