## snort의 구조
- sniffer --> preprocessor --> detection engine --> alert/logging

## snort의 버전 확인하기
$ snort -V

## snort 구동하기
$ snort -T -c /etc/snort/snort.conf

## snort rule 확인하기
$ cd /etc/snort/rules
$ ls

## snort 설정 파일 확인하기
$ vi /etc/snort/snort.conf

## snort 로그 확인하기
$ ls /var/log/snort

## snort 구동 확인하기 1
- Ubuntu
  - $ vi /etc/snort/rules/local.rules
  - $ alert icmp any any -> any any (sid:1000001;)
- Kali Linux
  - $ hping3 ubuntu_ip -a kali_ip --icmp
    - ICMP source 위조하기
- Ubuntu
  - $ snort -A console -q -u snort - g snort -c /etc/snort/snort.conf
    - snort 구동하기
  
## snort 구동 확인하기 2
- Ubuntu
  - $ vi /etc/snort/rules/local.rules
  - $ alert icmp any any -> ubuntu_ip any (msg: "Detect ICMP"; sid:1000001;)
- Kali Linux
  - $ hping3 ubuntu_ip -a kali_ip --icmp
    - icmp source 위조하기
- Ubuntu
  - $ snort -A console -q -u snort -g snort -c /etc/snort/snort.conf
    - snort 구동하기
  
## snort rule 구성하기 1
- $ alert tcp any $HTTP_Ports -> any 1024: (msg: "Detection"; content: "version"; content: "location"; within: 100; sid:1000001;)
  - HTTP_Ports로 정의된 포트로부터 1024번 이상 포트로 나가는 패킷에 대해
  - "version" 패턴과 일치하는 곳 기점 1,000byte 내에 "location" 패턴 나오면
  - msg에 정의된 내용으로 경보 발생

## snort rule 구성하기 2
- $ alert tcp any any -> any 5555
	(msg: "Detection"; content: "|1111|"; offset: 4; depth: 12;
    content: "|0000|"; distance: 2; within: 4;
    content: "|0000|"; distance: 2; within: 4;
    content: "|0000|"; distance: 2; within: 4;
    content: "|0000|"; distance: 2; within: 4; sid:1000001;)
  - 5555번 포트로 나가는 패킷에 대해
  - 시작에서 4-12byte 떨어진 곳에 "|1111|" 패턴 일치
  - cotent를 찾은 곳에서 2-4byte 떨어진 곳에 |0000|" 발견
  - 3번 더 패킷 일치
  - msg에 정의된 내용으로 경보 발생
    
## FTP root 로그인 탐지하기
- $ alert tcp any any -> dst_ip 21 (msg: "FTP root login"; content: "USER root"; nocase; sid:1000001;)
  - FTP 접속 시 USER 명령을 통해 ID 전달

## Telnet root 로그인 탐지하기
- $ alert tcp src_ip 23 -> any any (msg: "Telnet root login"; content: "login"; pcre: "\root.*#\"; nocase; sid:1000001;)
  - Telnet 접속 시 로그인 성공 메시지, shell로 평문 전달
  - 정규 표현식 : root@로 시작, 임의의 문자가 0회 이상 나타난 후 #을 포함하는 문자열 검사

## Telnet Brute Force/Dictionary Attack 패스워드 크래킹 탐지
- $ alert tcp src_ip 23 -> any any (msg: "Telnet Brute Force"; content: "Login incorrect"; nocase; threshold: type limit, track by_dst, count 5, seconds 1; sid:1000001;)
  - Telnet 응답 메시지에서 로그인 실패 탐지

## FTP Brute Force/Dictionary Attack 패스워드 크래킹 탐지
- $ alert tcp src_ip 21 -> any any (msg: "FTP Brute Force"; content: "Login incorrect"; nocase; threshold: type threshold, track by_dst, count 5, seconds 1; sid:1000001;)

## SSH Brute Force/Dictionary Attack 패스워드 크래킹 탐지
- $ alert tcp any any -> dst_ip any (msg: "SSH Brute Force"; content: "SSH-2.0"; nocase; threshold: type both, track by_src, count 5, seconds 1; sid:1000001;)
  - 로그인 요청 메시지에서 SSH-2.0 문자열 탐지

## HTTP GET Flooding Attack 탐지
- $ alert tcp any any -> dst_ip 80 (msg: "HTTP Flooding"; content: "GET /HTTP/1."; nocase; threshold, type threshold; track by_src, count 50, seconds 1; sid:1000001;)
  - HTTP 요청 메시지에서 "GET / HTTP 1." 문자열 탐지

## TCP SYN Flooding Attack 탐지
- $ alert tcp any any -> dst_ip 80 (msg: "TCP SYN Flooding"; flags: S; threshold: type threshold, track by_src, count 5, seconds 1; sid:1000001;)
  - HTTP 클라이언트의 TCP 요청 메시지에서 SYN Flag 탐지

## UDP SYN Flooding Attack 탐지
- $ alert udp any any -> dst_ip any -> (msg: "UDP Flooding"; threshold: type threshold, track by_src, count 5, seconds 1; sid:1000001;)

## 인터넷 구간의 사설 IP를 가진 패킷 탐지
- $ alert udp 10.0.0.0/8 any -> dst_ip any -> (msg: "abnormal packet"; sid:1000001;)
  - 인터넷에 돌아다니는 패킷 중 사설 IP 주소를 가진 패킷 : 조작된 IP 주소
  
## Source IP, Destination IP가 동일한 패킷 탐지
- $ alert ip any any -> dst_ip any (msg: "LAND Attack"; sameip; sid:1000001;)
  - LAND Attack에 사용되는 패킷 탐지

## 사설 IP 탐지 rule 1
- Ubuntu
  - $ alert icmp 10.0.0.0/8 any -> ubuntu_ip any (sid:1000001;)
    - 출발지 IP 주소가 A클래스 사설 IP 주소인 패킷 탐지 가능
- Kali Linux
  - $ hping3 ubuntu_ip -a 10.0.0.0 --icmp
    - 출발지 위장
- Ubuntu
  - $ snort -A console -q -u snort -g snort -c /etc/snort/snort.conf
    - snort 탐지
 
## 사설 IP 탐지 rule 2
- Ubuntu
  - $ alert icmp 172.16.0.0/12 any -> ubuntu_ip any (sid:1000001;)
    - 출발지 IP 주소가 B클래스 사설 IP 주소인 패킷 탐지 가능
- Kali Linux
  - $ hping3 ubuntu_ip -a 172.16.0.0 --icmp
    - 출발지 IP 위장
- Ubuntu
  - $ snort -A console -q -u snort -g snort -c /etc/snort/snort.conf
    - snort 탐지

