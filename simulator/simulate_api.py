from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import random
from datetime import datetime
import logging
from pydantic import BaseModel
# from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
# Instrumentator().instrument(app).expose(app)

PROTOCOLS = ['TCP', 'UDP', 'ICMP']
IPS = ['192.168.1.2', '192.168.1.3', '10.0.0.2', '8.8.8.8', '172.16.0.5']

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_packet(include_label=True, force_label=None):
    src = random.choice(IPS)
    dst = random.choice([ip for ip in IPS if ip != src])
    protocol = random.choice(PROTOCOLS)
    length = random.randint(20, 1500)
    timestamp = datetime.utcnow().isoformat()
    label = force_label if force_label else random.choices(['normal', 'anomaly'], weights=[0.85, 0.15])[0]

    # Inject anomaly pattern if needed
    if label == 'anomaly':
        anomaly_type = random.choice(['large_packet', 'weird_ip', 'bad_protocol', 'flood'])

        if anomaly_type == 'large_packet':
            length = random.randint(2000, 10000)  # unusually large
        elif anomaly_type == 'weird_ip':
            src = f"{random.randint(200,255)}.{random.randint(200,255)}.{random.randint(200,255)}.{random.randint(200,255)}"
        elif anomaly_type == 'bad_protocol':
            protocol = "UNKNOWN"
        elif anomaly_type == 'flood':
            dst = random.choice(IPS)
            src = dst  

    packet = {
        "src_ip": src,
        "dst_ip": dst,
        "protocol": protocol,
        "length": length,
        "timestamp": timestamp,
        "label": label  # For training or analysis
    }
    logger.info(f"Simulated packet: {packet}")

    if include_label:
        packet["label"] = label
    return packet

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class SimulateRequest(BaseModel):
    n: int

@app.post("/simulate_packets")
def simulate_single_packet(request: SimulateRequest):
    packets = []
    for _ in range(request.n):
        packet = generate_packet(include_label=True)
        packets.append(packet)
    # packet["label"] = "anomaly"  # force anomaly
    return packets


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5004)
