import pyshark
import joblib
import asyncio
import time

log_file = open("../logs.txt", "a")
# Fix event loop
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# Load model + scaler
model = joblib.load("models/nids_model_limited.pkl")
scaler = joblib.load("models/scaler_limited.pkl")

capture = pyshark.LiveCapture(interface='Wi-Fi')

flows = {}

print("🚀 Live NIDS Started...")

for packet in capture.sniff_continuously():
    try:
        if 'IP' not in packet:
            continue

        src = packet.ip.src
        dst = packet.ip.dst
        proto = packet.transport_layer

        if proto is None:
            continue

        src_port = packet[proto].srcport
        dst_port = packet[proto].dstport

        flow_id = (src, dst, proto, src_port, dst_port)

        length = int(packet.length)
        now = time.time()

        # Initialize flow
        if flow_id not in flows:
            flows[flow_id] = {
                "start_time": now,
                "fwd_packets": 0,
                "total_bytes": 0,
                "packet_lengths": [],
                "ack_count": 0
            }

        flow = flows[flow_id]

        # Update stats
        flow["fwd_packets"] += 1
        flow["total_bytes"] += length
        flow["packet_lengths"].append(length)

        # ACK flag detection
        if 'TCP' in packet:
            if hasattr(packet.tcp, 'flags'):
                if int(packet.tcp.flags, 16) & 0x10:
                    flow["ack_count"] += 1

        duration = now - flow["start_time"]

        # Wait for enough packets
        if flow["fwd_packets"] < 5:
            continue

        # ✅ CREATE FEATURES (MATCH TRAINING)
        flow_duration = duration
        total_fwd = flow["fwd_packets"]
        bytes_per_sec = flow["total_bytes"] / (duration + 1e-5)
        avg_pkt_len = sum(flow["packet_lengths"]) / len(flow["packet_lengths"])
        ack_flag_count = flow["ack_count"]

        features = [
            flow_duration,
            total_fwd,
            bytes_per_sec,
            avg_pkt_len,
            ack_flag_count
        ]

        # Scale
        features_scaled = scaler.transform([features])

        # Predict
        prediction = model.predict(features_scaled)

        if prediction[0] == 1:
            result = f"Intrusion | Length: {avg_pkt_len}"
        else:
            result = f"Normal | Length: {avg_pkt_len}"

        print(result)

        # ✅ WRITE TO FILE
        log_file.write(result + "\n")
        log_file.flush()

    except Exception as e:
        print("ERROR:", e)