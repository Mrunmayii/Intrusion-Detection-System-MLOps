import streamlit as st
import requests
import time
import threading
import pandas as pd
from metrics import packet_counter, start_metrics_server

start_metrics_server()

BASE_URL = "http://packet-capture-service:5001/"
PREPROCESSING_URL = "http://preprocessing-service:5002/"
ML_SERVICE_URL = "http://ml-service:5003/"
SIMULATE_URL = "http://simulator-service:5004/"

# BASE_URL = "http://localhost:5001/"
# PREPROCESSING_URL = "http://localhost:5002/"
# ML_SERVICE_URL = "http://localhost:5003/detect"
# SIMULATE_URL = "http://localhost:5004/"

if "live_capture_running" not in st.session_state:
    st.session_state["live_capture_running"] = False
if "live_packet_log" not in st.session_state:
    st.session_state["live_packet_log"] = []
if "capture_stop_event" not in st.session_state:
    st.session_state["capture_stop_event"] = threading.Event()

if "sim_packets" not in st.session_state:
    st.session_state["sim_packets"] = []
if "simulate_running" not in st.session_state:
    st.session_state["simulate_running"] = False
if "simulate_stop_event" not in st.session_state:
    st.session_state["simulate_stop_event"] = threading.Event()

st.markdown("""
    <style>
    .big-font {
        font-size:22px !important;
        font-weight: bold;
    }
    .packet-box {
        border: 1px solid #ddd;
        padding: 10px;
        border-radius: 5px;
        background-color: #380700;
    }
    </style>
""", unsafe_allow_html=True)

st.title("Real-time Intrusion Detection System")

status_color = "Running" if st.session_state["live_capture_running"] else "Stopped"
st.markdown(f"### Live Capture Status: {status_color}")

option = st.radio("Choose input method", ("Live Capture", "Simulate Packets"))

if option == "Live Capture":
    st.subheader("Live Packet Monitoring")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("▶️ Start Live Capture") and not st.session_state["live_capture_running"]:
            try:
                res = requests.post(f"{BASE_URL}start_capture")
                st.success(res.json())
                st.session_state["live_capture_running"] = True
                st.session_state["capture_stop_event"].clear()

                def capture_loop():
                    # while not stop_event.is_set():
                    while not st.session_state["capture_stop_event"].is_set():
                        try:
                            res = requests.get(f"{BASE_URL}get_packet", timeout=3)
                            packet = res.json()
                            detection = requests.post(f"{BASE_URL}analyze_packet", json=packet, timeout=3).json()
                            packet_display = {
                                "src_ip": packet.get("src_ip", "N/A"),
                                "dst_ip": packet.get("dst_ip", "N/A"),
                                "protocol": packet.get("protocol", "N/A"),
                                "length": packet.get("length", "N/A"),
                                "timestamp": packet.get("timestamp", "N/A"),
                                "Label": "Anomaly" if detection.get("anomaly", False) else "Normal",
                                "Reasons": "; ".join(detection.get("reasons", []))
                            }

                            st.session_state["live_packet_log"].append(packet_display)
                            if len(st.session_state["live_packet_log"]) > 20:
                                st.session_state["live_packet_log"] = st.session_state["live_packet_log"][-20:]

                            time.sleep(1)
                        except Exception as e:
                            st.error(f"Error during live capture: {e}")
                            st.session_state["live_capture_running"] = False
                            break

                threading.Thread(target=capture_loop, daemon=True).start()
            except Exception as e:
                st.error(f"Failed to start live capture: {e}")

    with col2:
        if st.button("⏹️ Stop Live Capture") and st.session_state["live_capture_running"]:
            st.session_state["live_capture_running"] = False
            st.session_state["capture_stop_event"].set()
            # try:
            #     res = requests.post(f"{BASE_URL}stop_capture")
            #     st.success(res.json())
            # except Exception as e:
            #     st.error(f"Failed to stop capture: {e}")
            try:
            # Download CSV
                if st.session_state["live_packet_log"]:
                    df = pd.DataFrame(st.session_state["live_packet_log"])
                    csv = df.to_csv(index=False).encode('utf-8')
                    st.download_button("📥 Download Captured Packets", csv, "captured_packets.csv", "text/csv")

                # Clear packets
                st.session_state["live_packet_log"] = []

                # Stop backend capture
                res = requests.post(f"{BASE_URL}stop_capture")
                st.success(res.json())
            except Exception as e:
                st.error(f"Failed to stop capture: {e}")

    with st.expander("Check Detected Malicious Packets"):

        if st.button("Check for Malicious Packets"):
            try:
                res = requests.get(f"{BASE_URL}malicious")
                data = res.json()
                count = data.get("count", 0)
                packets = data.get("packets", [])

                if count == 0:
                    st.success("No malicious packets detected so far.")
                else:
                    st.error(f"{count} malicious packet(s) detected!")
                    for pkt in packets:
                        with st.container():
                            st.markdown("---")
                            st.markdown(f"<div class='packet-box'><b>Source IP:</b> {pkt['src_ip']}<br>"
                                        f"<b>Destination IP:</b> {pkt['dst_ip']}<br>"
                                        f"<b>Protocol:</b> {pkt['protocol']}<br>"
                                        f"<b>Length:</b> {pkt['length']}<br>"
                                        f"<b>Timestamp:</b> {pkt['timestamp']}<br>"
                                        f"<b>Reasons:</b> {'; '.join(pkt['reasons'])}</div>", unsafe_allow_html=True)
            except Exception as e:
                st.error(f"Failed to fetch malicious packets: {e}")

    with st.expander("Recent Captured Packets (Live View)", expanded=True):
        if st.session_state["live_capture_running"]:
            try:
                res = requests.get(f"{BASE_URL}get_packet")
                packet = res.json()
                detection = requests.post(f"{BASE_URL}analyze_packet", json=packet).json()

                packet_display = {
                    "src_ip": packet.get("src_ip", "N/A"),
                    "dst_ip": packet.get("dst_ip", "N/A"),
                    "protocol": packet.get("protocol", "N/A"),
                    "length": packet.get("length", "N/A"),
                    "timestamp": packet.get("timestamp", "N/A"),
                    "Label": "Anomaly" if detection.get("anomaly", False) else "Normal",
                    "Reasons": "; ".join(detection.get("reasons", []))
                }

                st.session_state["live_packet_log"].append(packet_display)
                if len(st.session_state["live_packet_log"]) > 20:
                    st.session_state["live_packet_log"] = st.session_state["live_packet_log"][-20:]

            except Exception as e:
                st.error(f"Error fetching packet: {e}")

            if st.session_state["live_packet_log"]:
                df = pd.DataFrame(st.session_state["live_packet_log"])
                st.dataframe(st.session_state["live_packet_log"], use_container_width=True)
                time.sleep(2)
                st.rerun()
            else:
                st.info("No packets captured yet.")
            # if st.session_state["live_packet_log"]:
            # df = pd.DataFrame(st.session_state["live_packet_log"])

            # def highlight_malicious(row):
            #     return ['background-color: #ff9999' if row['Label'] == 'Anomaly' else '' for _ in row]

            # st.dataframe(df.style.apply(highlight_malicious, axis=1), use_container_width=True)
            # time.sleep(2)
            # st.rerun()

elif option == "Simulate Packets":
    st.subheader("Simulate & Analyze Packets")

    n_packets = st.selectbox("How many packets to simulate?", [5, 10, 20, 50], index=0)

    col1, col2 = st.columns(2)
    with col1:
        if st.button(f"Simulate {n_packets} Packets"):
            try:
                requests.post(f"{PREPROCESSING_URL}clear_results")
                packets = requests.post(f"{SIMULATE_URL}simulate_packets", json={"n": n_packets}).json()
                for pkt in packets:
                    requests.post(f"{PREPROCESSING_URL}extract", json=pkt)

                st.success(f"Simulated and sent {len(packets)} packets. Please wait {5} seconds for analysis.")
                st.session_state["simulate_triggered"] = True
                st.session_state["last_sim_time"] = time.time()

                st.rerun()

            except Exception as e:
                st.error(f"Simulation failed: {e}")

    with col2:
        if st.button("🔄 Refresh Results"):
            st.session_state["simulate_triggered"] = True
            st.session_state["last_sim_time"] = time.time()
            st.rerun()

    if st.session_state.get("simulate_triggered", False):
        elapsed = time.time() - st.session_state.get("last_sim_time", 0)
        if elapsed < 5:
            st.info(f"⏳ Waiting for analysis to complete ({5 - int(elapsed)}s)...")
            time.sleep(1)  # brief delay before rerun
            st.rerun()
        else:
            try:
                res = requests.get(f"{PREPROCESSING_URL}results")
                results = res.json().get("results", [])

                if not results:
                    st.warning("No results yet. Please try refreshing.")
                else:
                    st.session_state["simulate_triggered"] = False
                    st.dataframe(results, use_container_width=True)

                    anomalies = [r for r in results if r["anomaly"]]
                    if anomalies:
                        st.error(f"{len(anomalies)} anomaly packet(s) detected!")
                    else:
                        st.success("All packets are normal.")

            except Exception as e:
                st.error(f"Failed to fetch results: {e}")
