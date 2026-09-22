flows = {}

def get_flow_key(packet):
    if packet.haslayer("IP"):
        ip = packet["IP"]
        proto = ip.proto
        
        src = ip.src
        dst = ip.dst
        
        sport = packet.sport if hasattr(packet, "sport") else 0
        dport = packet.dport if hasattr(packet, "dport") else 0

        return (src, dst, sport, dport, proto)
    
    return None


def update_flow(packet):
    key = get_flow_key(packet)
    if key is None:
        return None

    if key not in flows:
        flows[key] = {
            "packets": [],
            "start_time": packet.time
        }

    flows[key]["packets"].append(packet)

    return flows[key]