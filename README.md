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
  - 
## snort rule 구성하기 3

## snort rule 구성하기 4

## snort rule 구성하기 5

## snort
