---
layout: post
title: "SKT Telecom Data breach"
date: 2025-06-04
category: Python
image: assets/img/blog/async-await.jpg
author: 김윤중
tags: Malware Analysis, BackDoor, 
---

## SKT 침해사고 보고서

### 1. 사고 개요 
2025년 4월 19일 23시 40분경 SK Telecom(1)의 무선 인터넷 통신 5G/LTE 서비스를 위해 USIM 정보를 인증하는 **HSS (중앙 데이터베이스 및 인증 관련 기능을 수행하는 장비)(2)** 서버가 해커의  의한 악성코드로 **가입자 전화번호, 가입자식별키(IMSI) 등 USIM 복제에 활용될 수 있는 4종과 USIM 정보 처리 등에 필요한 SKT 관리용 정보 21종이 유출(3)**되는 침해사고가 발생하였다. 이후  내용에서 상세히 서술을 하겠다.


### 2. 사고 원인
**- BDFdoor**  

<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT1.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>Github : gwillgues/BPFDoor</figcaption>
</figure>


침투 경로는 밝혀지지 않았으며, **HSS서버에 BPFDoor계열의 악성코드 4종이 발견**이 되었다. 해당 웹 페이지는 이번에 사용된 것으로 예상되는 백도어의 원본이 되는 소스코드가 첨부되어있다. 소스코드의 핵심 부분을 통하여 백도어의 작동을 분석하였다.



<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT2.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
</figure>
<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT3.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>BPFdoor.c main함수</figcaption>
</figure>


main함수를 확인할 시 사칭할 데몬 프로세스 목록들이 보인다. 대부분 리눅스의 시스템 데몬으로 지정을 하였으며 10개의 목록 중 하나를 지정하여 프로세스의 이름을 설정한다. 정상 시스템으로 위장하여 탐지를 회피하려는 의도가 보인다

<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT4.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>BPFdoor getshell 함수</figcaption>
</figure>

Iptables를 통하여 리버스 셸을 연결하기 위한  방화벽을 무력화하려는 시도도 발견하였다. 실제로 데이터가 유출된 SKT사에서 확인된 BPFdoor 악성코드에도 리버스 셸을 연결하기 위한 방화벽을 무력화하는 코드가 있었을 가능성이 농후하다. 


<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT5.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>BPFdoor packet_loop 함수</figcaption>
</figure>
  

Packet_loop함수 내부에 변수 선언부를 살펴보면, 수신된 패킷에서 IP및 TCP,UDP 헤더를 파싱하고, magic_packet 구조체 포인터로 패킷을 변환한다.  

<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT6.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
</figure>
<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT7.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>BPFdoor packet_loop 함수</figcaption>
</figure>


이 백도어의 작동 트리거가 되는 핵심 부분이다. Bpf_code배열은 BPF(Berkeley Packet Filter)규칙을 담고 있으며, 이를 통하여 조건에 맞는 패킷만 수신하도록 설정하였다.  

<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT8.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>BPFdoor packet_loop 함수</figcaption>
</figure>

소켓으로부터 데이터를 받아 IP해더 파싱과 오류 검출을 수행한다. ip해더의 프로토콜을 switch case문으로 해당 프로토콜에 맞게 추가 처리를 해주어 매직 패킷을 mp에 대입을 해준다.

<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT9.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>BPFdoor packet_loop 함수</figcaption>
</figure> 

bip(백도어 ip로 추정)을 설정한다. 부모 프로세스는 자식 프로세스를 생성 후 종료되며 자식 프로세스는 /usr/libexec/postfix/master로 위장한다. 현재 디렉토리를 /(root) 이동한 다음 세션분리를 통하여 자식프로세스는 시스템 데몬으로 완전하게 위장한다.  
Rc4 암복호화를 위하여 Crypto_ctx와 decript_ctx를 설정해준다.

<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT10.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>BPFdoor packet_loop 함수</figcaption>
</figure>
logon 함수를 통하여 명령구문을 복호화 하여 해당 케이스에 맞는 기능을 수행하여 백도어의 기능을 수행하게 된다.

<figure style="text-align: center;">
  <img src="/assets/img/blog/SKT11.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>BPFdoor Shell 함수</figcaption>
</figure>
 Shell 함수의 일부분 중 원격 Shell을 연결하기 위한 코드도 발견이 되었다. 이로써 공격자는 원격 셸을 시스템을 완전하게 장악을 하게 된다.

BPF도어는 시스템에 몰래 잠복한 뒤, 특정 매직 패킷(Magic Packet)을 수신하면 활성화되는 구조이며 매직 패킷은 네트워크상에서 특별한 패턴을 가져 일반 보안 장비 탐지를 우회할 수 있다.  BPF도어는 정상 시스템 프로세스처럼 위장해 탐지를 회피하고, 네트워크 트래픽을 위장해 방화벽 탐지를 우회하는 고도의 은밀성을 갖춘 백도어이다. 설치 경로는/tmp/ abbix_agent.log, /bin/vmtoolsdsrv 등 포렌식 분석을 어렵게 하는 은닉 경로를 사용하였다. 공격자는 전용 컨트롤러를 이용해 감염된 서버에 접속한 뒤, 암호 기반 인증 절차를 거쳐 역방향 셸(reverse shell)을 열고 원격으로 시스템을 제어하는 것으로 분석된다.  레드멘션이 최근 BPF도어를 오픈소스로 풀었기 때문에 이번 공격의 배후를 특정하기는 어려운 상황이다(5).  

## 3. 사후 대응 방안
 해당 악성코드가 발견된 장비는 악성코드 삭제 후 해당 장비를 즉시 격리 조치를 한다. 정확한 네트워크 구성도는 알 수 없지만 HSS서버는 중요한 데이터를 저장하는 서버이기에 앞 단에 여러 장비를 지나 접근하는 서버일 수도 있다. 즉 다른 서버들도 해당 악성코드에 감염되었을 가능성이 높다. 사내에 있는 모든 장비를 점검하여 악성코드 감염 여부를 파악하고 새로운 보안 정책(소프트웨어 업데이트, 솔루션 추가)을 업데이트한다.  

 데이터 유출로 인한 불법 유심 복제 방지를 위해 유심보호 서비스를 제공, FSD(Fraud Detection System) 불법 복제 유심인증을 실시간 감지/차단 하는 시스템을 최고 수준으로 격상해 운영하여 유심 복제를 예방한다.

## 4. 예상되는 피해 시나리오
 유심 또는 통신사와 관련된 사회공학 기법이 유행을 하게 될 것이다. 유심 무료 교체, 타 통신사 할인 등 불안한 군중 심리를 이용하여 적지 않은 피해가 발생하게 될 가능성이 높다.

또한 SKT는 유심을 교체하기 위한 막대한 비용을 마련해야 하며, 단순 계단을 하여도 7700원 * 2500만 = 2000억원에 가까운 천문학적인 비용이 필요하다. 집단 소송으로 발생되는 민사상 배상, 개인정보 유출로 인한 막대한 금액의 과태료(벌금), 이용자 이탈 및 기업 신뢰도 하락으로 인하여 많은 기업 운영에 영향이 미칠 정도로 큰 손실이 발생될 것으로 예상된다.
## 5. 사전 예방 방안
 SK텔레콤 해킹 사고가 백도어 악성코드 공격으로 발생했다는 분석이 나오고 있다. 보안업계는 비용 및 관리적 부담이 큰 '서버 보안' 체계가 부실했던 게 근본적 원인이라며, 이번 사건을 계기로 산업별 경각심이 커져야 한다고 보고 있다.
이번 침해사고는 이미 조짐이 있었다. 홍콩, 미얀마, 말레이시아, 이집트 등 통신, 금융, 소매등 분야를 가리지 않고 BPDdoor의 공격 표적이 되었다(7).  전세계에서 유행하는 공격 기법의 트랜드를 파악하여 사전에 충분히 조치를 취할 수 있는 부분이었다. 정기적인 시스템 업데이트와 취약점 분석을 통해 최신 보안 기술을 도입하고, 시스템의 약점을 사전에 파악하여 악성코드 침투를 예방한다. 또한 AI기반 IPS/IDS, EDR등 보안 장비를 통해 조금이라도 공격 성공 가능성을 낮추며, 관련 연구 개발에 대한 투자를 확대함으로써 고도화된 공격을 탐지하고 방어할 수 있는 솔루션을 구축한다.
이번 SKT의 침해 사고는 기존의 보안 조치만으로는 충분하지 않다는 사실을 보여준다. 이번 사례의 BPFdoor는 고도화된 백도어이다. 앞으로도 이처럼 더욱 고도화된 공격이 발전되어 기존의 보안 조치가 무력화가 될 가능성이 점점 높아질 것이다. 새로운 솔루션의 및 정책을 연구를 하여 발전시켜야 한다.

참고 문헌
1. SK텔레콤 사이버 침해 사고 관련 FAQ :  https://news.sktelecom.com/211630
2. Hss 란 : https://www.clien.net/service/board/lecture/18963553
3. 해럴드 경제 : https://biz.heraldcorp.com/article/10476673?ref=naver
4. 과학기술정보통신부 과기정통부, SKT 침해사고 1차 조사결과 발표 : https://www.msit.go.kr/bbs/view.do?sCode=user&mPid=208&mId=307&bbsSeqNo=94&nttSeqNo=3185757
5. 보안뉴스 BPF도어 : https://www.boannews.com/media/view.asp?idx=137027&amp;kind=&amp;sub_kind=
6. Github gwillgues/BPFDoor : https://github.com/gwillgues/BPFDoor
7. 디지털 데일리 : https://m.ddaily.co.kr/page/view/2025042415081342414
