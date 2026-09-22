def extract_features(packet):
    try:
        length = int(packet.length)
        protocol = packet.highest_layer

        return [
            length,
            1 if protocol == "TCP" else 0,
            1 if protocol == "UDP" else 0,
            0, 0  # placeholder for now
        ]
    except:
        return None