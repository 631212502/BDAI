import pyshark

def parse_goose_with_pyshark(pcap_file):
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter='goose'  # 只过滤GOOSE报文
    )
    goose_data = []
    
    for packet in cap:
        try:
            if hasattr(packet, 'goose'):
                goose_info = {
                    'frame_number': packet.number,
                    'timestamp': packet.sniff_time,
                    'src_mac': packet.eth.src,
                    'dst_mac': packet.eth.dst,
                    'appid': getattr(packet.goose, 'appid', 'N/A'),
                    'gocb_ref': getattr(packet.goose, 'gocbref', 'N/A'),
                    'time_allowed': getattr(packet.goose, 'timeallowedtolive', 'N/A'),
                    'st_num': getattr(packet.goose, 'stnum', 'N/A'),
                    'sq_num': getattr(packet.goose, 'sqnum', 'N/A'),
                    'test': getattr(packet.goose, 'test', 'N/A'),
                    'conf_rev': getattr(packet.goose, 'confrev', 'N/A')
                }
                goose_data.append(goose_info)
        except AttributeError as e:
            print(f"解析错误: {e}")
            continue
    
    return goose_data

# 使用示例
goose_packets = parse_goose_with_pyshark('dataset/goose.pcap')
for pkt in goose_packets:
    #print(pkt)
    print(f"APPID: {pkt['appid']}, GOCBRef: {pkt['gocb_ref']}")