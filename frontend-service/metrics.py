from prometheus_client import start_http_server, Counter
import threading

packet_counter = Counter("streamlit_packets_handled", "Number of packets processed in frontend")

def start_metrics_server(port=8000):
    def run():
        start_http_server(port)
        print(f"Prometheus metrics server running on port {port}")
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
