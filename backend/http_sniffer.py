from scapy.all import sniff, TCP, IP, Raw

# 웹 서버 포트 번호
TARGET_PORT = 80

def process_packet(packet):
    # IP와 TCP 레이어가 모두 있는지 확인
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        # 80번 포트와 관련된 패킷만 잡기
        if src_port == TARGET_PORT or dst_port == TARGET_PORT:
            # IP 주소 추출
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # [정보 출력] 누가 누구에게 보냈는지
            info = f"[출발지 {src_ip}:{src_port}] -> [도착지 {dst_ip}:{dst_port}]"
            
            # 깃발(Flags) 확인 (SYN, ACK, PUSH 등)
            flags = packet[TCP].flags
            
            # 데이터(Raw Layer)가 있다면 출력 (HTTP 내용)
            if packet.haslayer(Raw):
                # 바이트 데이터를 문자열로 디코딩 (깨진 문자는 무시)
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # HTTP 요청(GET)이나 응답(HTTP/1.1)인 경우만 출력
                    if "GET" in payload or "HTTP" in payload:
                        print(f"\n🔎 [HTTP 패킷 감지] {info} | Flags: {flags}")
                        print("-" * 50)
                        # 내용이 너무 길면 앞부분 500글자만 출력
                        print(payload[:500]) 
                        print("-" * 50)
                except:
                    pass
            else:
                # 데이터가 없는 패킷 (3-way handshake 과정: SYN, ACK 등)
                print(f"🔔 [TCP 제어 패킷] {info} | Flags: {flags}")

if __name__ == "__main__":
    print(f"📡 HTTP 스니퍼 시작... (Port {TARGET_PORT} 감시 중)")
    
    # 친구 컴퓨터와 통신할 때는 iface="en0" (와이파이)
    # 혼자 테스트할 때는 iface="lo0"
    try:
        sniff(iface="en0", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n종료")