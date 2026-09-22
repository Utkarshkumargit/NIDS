# import streamlit as st
# import time

# st.title("Real-Time NIDS Dashboard")

# placeholder = st.empty()

# for _ in range(1000):  # simulate loop
#     try:
#         with open("../logs.txt", "r") as f:
#             lines = f.readlines()

#         last_lines = lines[-10:]

#         with placeholder.container():
#             for line in last_lines:
#                 if "⚠️" in line:
#                     st.error(line.strip())
#                 else:
#                     st.success(line.strip())

#         time.sleep(2)

#     except:
#         st.warning("Waiting for detector...")
#         time.sleep(2)

import streamlit as st
import time
import pandas as pd

st.set_page_config(page_title="NIDS Threat Monitor", layout="wide")

st.title("🛡️ NIDS Security Operations Center")

# --- Persistent Metrics Layout ---
m1, m2, m3 = st.columns(3)
total_captured = m1.metric("Total Packets", 0)
# delta_color="inverse" makes the "increase" in threats appear red (bad)
threat_count_metric = m2.metric("Threats Detected", 0, delta_color="inverse")
safety_score = m3.metric("System Integrity", "100%")

# Create placeholders for the dynamic UI elements
chart_placeholder = st.empty()
log_placeholder = st.empty()

def parse_logs():
    """Reads the log file and categorizes the data."""
    try:
        with open("../logs.txt", "r") as f:
            lines = f.readlines()
            
        data = []
        threats = 0
        for line in lines:
            is_threat = "Intrusion" in line
            if is_threat: 
                threats += 1
            
            # Extracting length from "Intrusion | Length: 1200" or "Normal | Length: 64"
            try:
                length = int(line.split("Length: ")[1])
            except:
                length = 0

            data.append({
                "Status": "⚠️ ATTACK" if is_threat else "✅ NORMAL",
                "Length": length,
                "Type": "Intrusion" if is_threat else "Normal"
            })
        return pd.DataFrame(data), threats, len(lines)
    except FileNotFoundError:
        return pd.DataFrame(), 0, 0

# --- Main Refresh Loop ---
for _ in range(1000):
    df, total_threats, total_packets = parse_logs()

    if not df.empty:
        # 1. Update Top Metrics
        total_captured.metric("Total Packets", total_packets)
        threat_count_metric.metric("Threats Detected", total_threats)
        
        integrity = ((total_packets - total_threats) / total_packets) * 100
        safety_score.metric("System Integrity", f"{integrity:.1f}%")

        with chart_placeholder.container():
            st.write("### 📈 Traffic Analysis")
            # Create a simple distribution count for the chart
            chart_data = df['Type'].value_counts()
            # Streamlit's built-in bar chart
            st.bar_chart(chart_data, width="stretch")

        with log_placeholder.container():
            st.write("### 🛰️ Live Security Feed (Last 15 Packets)")
            # 2026 Compliant: width="stretch" replaces use_container_width=True
            st.dataframe(df.tail(15), width="stretch", hide_index=True)

    else:
        st.info("📡 Waiting for live packet data from detector...")

    time.sleep(2)