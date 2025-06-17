---
layout: post
title: "IDS/IPS개발을 통한 공격 분석 및 방어"
date: 2025-05-28
category: Python
image: assets/img/blog/IPS.png
author: 김윤중
tags: Python Flask, sockiet, IDS, IPS, Security
---


## IDS/IPS 
**IPS/IDS 시스템 개발을 공격 분석 및 방어를 해보았습니다.**  
Snort와 유사하게 규칙을 구성을 하였으며, 패킷 데이터를 json으로 구조화하여  
이용자가 더욱 쉽고 간편하게 탐지를 할 수 있도록 하였습니다. 

### Rule 
Src_ip, Src_port - Dst_ip, Dst_port [option : value] [msg : 출력할 내용]


### Rule option

Content : 매칭할 데이터  
[ Brute Force Search ]  

protocol : tcp/udp/arp 등등  
layer : tcp/udp/arp 등등  
정확한 네이밍으로 option을 적어야 작동.  
[ Hash ]

layer와 protocol은 동일한 의미를 가집니다.

any any - any any [layer : tcp] [flags : fin] [msg : 스텔스 스캔 탐지]  
모든 tcp 트래픽의 flag가 fin인 패킷을 탐지 시 "스텔스 스캔 탐지" 출력.  
  
any any - any any [layer : tcp] [content : hi] [msg : server hi 감지]  
모든 tcp 트래픽의 데이터 안에 hi라는 문자열 포함 시 "server hi 감지" 출력.  

## 🔍 GUI환경

<figure style="text-align: center;">
  <img src="/assets/img/blog/IPS.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>메인화면</figcaption>
</figure>

한눈에 직관적으로 알기 쉽게 페이지를 구성  
화면 패킷(왼), 이벤트 목록(오), 트래픽 사용량 그래프(하)   

<figure style="text-align: center;">
  <img src="/assets/img/blog/IPS1.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>메인화면</figcaption>
</figure>

오른쪽 작업바를 이용하여 로그아웃 및 규칙 관리, 관리자페이지(관리자만 볼 수 있게 설정)으로
이동을 할 수 있습니다.

<figure style="text-align: center;">
  <img src="/assets/img/blog/IPS2.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>규칙관리페이지</figcaption>
</figure>

규칙 페이지에서 사용자가 탐지할 패킷의 규칙과, 탐지만 할지 차단을 할지 직접적으로 설정을  
할 수 있습니다. 해당 화면에 보인 규칙은 SQL Injection을 탐지하는 규칙과 
ping을 탐지하는 규칙이 실험적으로 적용이 되어 있습니다.  

<figure style="text-align: center;">
  <img src="/assets/img/blog/IPS3.png" alt="Heartbeat Diagram" style="max-width: 100%; border-radius: 12px;" />
  <figcaption>메인페이지</figcaption>
</figure>
ICMP탐지를 위해 ping을 임의적으로 보내어 정상적으로 탐지가 되는지 확인을 하였습니다.  
이벤트 목록을 클릭하여 자세한 보기 사항도 확인을 할 수 있게 구성을 해놓았습니다.

자세한 탐지 알고리즘은 블로그의 탐지 알고리즘 리뷰를 확인하여 주시길 바랍니다.


총 작성된 파이썬 코드 : 987  
Github : https://github.com/kimyunjung0220/IPS_System

Date : 2025-06-11 Wed