from fastapi import FastAPI
import threading
import pyshark
import requests
import uvicorn
from datetime import datetime
import time
import threading
from pydantic import BaseModel
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
Instrumentator().instrument(app).expose(app)

PREPROCESSING_URL = "http://preprocessing-service:5002/extract"
# PREPROCESSING_URL = "http://localhost:5002/extract"

captured_packets = []  
malicious_packets = [] 

last_send_time = time.time()

class Packet(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    timestamp: str

@app.get("/get_packet")
def get_latest_packet():
    if captured_packets:
        return captured_packets[-1]
    else:
        return {
            "src_ip": "0.0.0.0",
            "dst_ip": "0.0.0.0",
            "protocol": "TCP",
            "length": 0,
            "timestamp": datetime.now().isoformat()
        }

@app.post("/analyze_packet")
def analyze_packet(packet: Packet):
    # print("Received packet in analyze_packet:", packet)
    try:
        packet_dict = packet.dict()
        response = requests.post(PREPROCESSING_URL, json=packet_dict).json()
        print("resp from preprocess ", response)

        if response.status_code == 200:
            preprocessed = response.json()
            if preprocessed.get("anomaly", False):
                malicious_packets.append({
                    **packet_dict,
                    "reasons": preprocessed.get("reasons", [])
                })
            return preprocessed
        else:
            return {
                "error": f"Preprocessing service returned {response.status_code}",
                "details": response.text
            }
    except Exception as e:
        return {"error": str(e)}

@app.get("/malicious")
def get_malicious_packets():
    return {
        "count": len(malicious_packets),
        "packets": malicious_packets
    }
 
capture_thread = None
capture_thread_stop = False

def capture_packets():
    print("in packet capture")
    global capture_thread_stop
    capture_thread_stop = False
    capture = pyshark.LiveCapture(interface="any")
    batch = []
    last_sent_time = time.time()
    for packet in capture.sniff_continuously():
        if capture_thread_stop:
            print("Capture thread stopping.")
            break
        try:
            if 'IP' in packet:
                proto = packet.transport_layer or "UNKNOWN"
                pkt_data = {
                    "src_ip": packet.ip.src,
                    "dst_ip": packet.ip.dst,
                    "protocol": proto,
                    "length": int(packet.length),
                    "timestamp": datetime.now().isoformat()
                }
                captured_packets.append(pkt_data)
                if len(captured_packets) > 1000:
                    captured_packets.pop(0)

                # print(pkt_data)
                # batch.append(pkt_data)
                try:
                        response = requests.post(PREPROCESSING_URL, json=pkt_data)
                        if response.status_code != 200:
                            print(f"Preprocessing service error: {response.status_code} - {response.text}")
                except Exception as e:
                    print("Error sending packet:", e)
            else:
                print("skipping packet w/o IP layer")
        except Exception as e:
            print("Error parsing packet:", e)

@app.post("/start_capture")
def start_capture():
    global capture_thread
    global capture_thread_stop
    if capture_thread is not None and capture_thread.is_alive():
        return {"status": "capture already running"}
    capture_thread_stop = False
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.daemon = True
    capture_thread.start()
    return {"status": "capture started"}

@app.post("/stop_capture")
def stop_capture():
    global capture_thread_stop
    capture_thread_stop = True
    return {"status": "capture stopping"}

@app.get("/")
def root():
    return {"status": "Packet sniffer running"}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=5001, reload=True)
