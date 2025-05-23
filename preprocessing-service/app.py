from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Optional
import uvicorn
import asyncio
import httpx
from prometheus_fastapi_instrumentator import Instrumentator

MODEL_URL = "http://ml-service:5003/detect_batch"
# MODEL_URL = "http://localhost:5003/detect_batch"


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
    protocol_map = {
        "TCP": 1,
        "UDP": 2,
        "DNS": 3,
        "ICMP": 4
    }
    return {
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "protocol": protocol_map.get(packet.protocol.upper(), 0),
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
    reverse_protocol_map = {
        1: "TCP",
        2: "UDP",
        3: "DNS",
        4: "ICMP"
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(MODEL_URL, json=packets)
            print(f"Sent batch of {len(packets)} packets, status: {response.status_code}")
            if response.status_code == 200:
                results = response.json().get("results", [])
                print("ML service result:", results)
                print("Parsed anomaly type:", type(results[0]["anomaly"]))

                # return results
                combined = []
                for pkt, res in zip(packets, results):
                    combined.append({
                        "src_ip": pkt["src_ip"],
                        "dst_ip": pkt["dst_ip"],
                        "protocol": reverse_protocol_map.get(pkt["protocol"], "Other"),
                        "length": pkt["length"],
                        "timestamp": pkt["timestamp"],
                        "anomaly": res["anomaly"],
                        "label": "Anomaly" if str(res["anomaly"]).lower() == "true" else "Normal",
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


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=5002, reload=True)

