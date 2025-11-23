import socket
from scapy.all import DNS, DNSQR, DNSRR

# 설정
HOST = '0.0.0.0'
PORT = 53
MY_DOMAIN = "network.local."
MY_IP = [본인 서버 IP 주소]

def run_server():
    # 1. 표준 UDP 소켓 생성
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # 2. 53번 포트 열기 (관리자 권한 필요)
        sock.bind((HOST, PORT))
        print(f"DNS 서버 실행 중... ({HOST}:{PORT})")
        print(f"   타겟 도메인: {MY_DOMAIN}")
        print("   (종료하려면 Ctrl + C를 누르세요)")
        
        while True:
            # 3. 데이터 수신 대기
            data, addr = sock.recvfrom(1024)
            
            try:
                # 4. Scapy로 데이터 해석
                dns_req = DNS(data)
                
                # 쿼리 패킷인지 확인
                if dns_req.qr == 0 and dns_req.haslayer(DNSQR):
                    qname = dns_req[DNSQR].qname.decode('utf-8')
                    print(f"[+] 요청 수신: {qname} (from {addr})")
                    
                    if qname == MY_DOMAIN:
                        # 5. 응답 패킷 생성
                        dns_resp = DNS(
                            id=dns_req.id, # 요청 ID와 동일하게
                            qr=1,          # 응답(Response) 플래그
                            aa=1,          # 권한 있음(Authoritative)
                            rd=dns_req.rd, # 재귀 요청 플래그 복사
                            qd=dns_req[DNSQR], # 질문 섹션 복사
                            an=DNSRR(      # 답변 섹션 추가
                                rrname=MY_DOMAIN,
                                type='A',
                                rclass='IN',
                                ttl=60,
                                rdata=MY_IP
                            )
                        )
                        
                        # 6. 소켓을 통해 전송 (bytes로 변환)
                        sock.sendto(bytes(dns_resp), addr)
                        print(f"  -> 응답 전송 완료: {MY_IP}")
                    else:
                        print(f"  -> 무시함 (다른 도메인)")
                        
            except Exception as e:
                print(f"[오류] 패킷 처리 중 문제 발생: {e}")

    except PermissionError:
        print("\n[!] 오류: 관리자 권한이 필요합니다.")
        print("    'sudo python3 dns_server.py' 명령어로 실행해주세요.")
    except OSError as e:
        print(f"\n[!] 오류: 포트를 열 수 없습니다. 이미 실행 중인 서버가 있는지 확인하세요.\n    {e}")
    finally:
        sock.close()

if __name__ == '__main__':
    run_server()
