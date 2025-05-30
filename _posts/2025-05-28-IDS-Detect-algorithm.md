---
layout: post
title: "IDS Detect algorithm review"
date: 2025-05-28
category: Python
image: assets/img/blog/async-await.jpg
author: 김윤중
tags: Python Data Structure Hash, Brute Force Search
---


## IDS 탐지 알고리즘
**이번에 사용된 IPS/IDS 시스템에 적용이 된 IDS 탐지 알고리즘입니다.**  
Snort와 유사하게 규칙을 구성을 하였으며, 바이너리를 jason으로 파싱을 하였으며,  
이를 기반으로 문자열 탐색을 하여 아주 강력한 탐지 기능을 발휘할 수 있습니다.  

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

## 🔍 Packet Sniff module 분석

<pre>

import pyshark
import re
import json
import logging

def trans_json(data : str) -> json:
    data_json = {}
    key = None
    object_key = None
    data = data.split("\n")
    for line in data:
        if line.startswith('Layer'):
            key = line
            data_json[key] = {}
            
        elif line.startswith('\t'):
            line = line.lstrip()
            if "=" in line:
                end = line.find("=")
            else:
                end = line.find(":")
                
            start = line.find("\t") + 1
            
            object_key = line[start:end]
            value = line[end+1:]
            data_json[key][object_key] = value
    system.wirte_packet(data_json)
    data = json.dumps(data_json, ensure_ascii=False)
    return data
    
        
def trans_data(data : str) -> dict:
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[mK]')
    data = re.sub(ansi_escape, '', data)
    data = data.replace("\n:", "\n")
    return data

def get_packet(callback:None, func:None) -> json:
    get_sniff = pyshark.LiveCapture(interface=system.get_interface())
    for packet in get_sniff.sniff_continuously():
        packet = trans_data(str(packet))
        packet = trans_json(packet)
        detect = threading.Thread(target=detective_opensive, args=(packet,func), daemon=True)
        detect.start()
        callback('send_packet', {"data" : packet})
</pre>

모듈은 Wire Shark의 pyshark모듈을 사용하였으며,  
socket을 열어 패킷을 직접 덤프할 수도 있지만,  
시간 절약을 위하여 pyshark를 사용하였습니다.  

sniff_continuously() 메서드를 이용하여 패킷을 추출하였고,  
리턴을 하게 되면 이더넷이 닫히게 되어 제기능을 하지 못하여  
callback 함수를 사용하여 보다 더 빠르고 효율적으로 패킷을  
처리할 수 있도록 하였습니다.  

Trans_data 함수를 통하여 Ascii escape를 정규식으로 제거를 하였으며,  
Trans_json 함수를 통하여 패킷의 내용들을 json화를 해주었습니다.


### 결과


**추출된 TCP 패킷**
<pre>
{
    "Layer ETH": {
        "Destination": " 00:50:56:e8:48:61",
        "Address": " 00:0c:29:34:b9:de",
        ".... ..0. .... .... .... .... ": " LG bit: Globally unique address (factory default)",
        ".... ...0 .... .... .... .... ": " IG bit: Individual address (unicast)",
        "Source": " 00:0c:29:34:b9:de",
        "Type": " IPv4 (0x0800)"
    },
    "Layer IP": {
        "0100 .... ": " Version: 4",
        ".... 0101 ": " Header Length: 20 bytes (5)",
        "Differentiated Services Field": " 0x00 (DSCP: CS0, ECN: Not-ECT)",
        "0000 00.. ": " Differentiated Services Codepoint: Default (0)",
        ".... ..00 ": " Explicit Congestion Notification: Not ECN-Capable Transport (0)",
        "Total Length": " 40",
        "Identification": " 0x03d5 (981)",
        "Flags": " 0x40, Don't fragment",
        "0... .... ": " Reserved bit: Not set",
        ".1.. .... ": " Don't fragment: Set",
        "..0. .... ": " More fragments: Not set",
        "...0 0000 0000 0000 ": " Fragment Offset: 0",
        "Time to Live": " 64",
        "Protocol": " TCP (6)",
        "Header Checksum": " 0x400b [validation disabled]",
        "Header checksum status": " Unverified",
        "Source Address": " 192.168.35.128",
        "Destination Address": " 13.107.5.93"
    },
    "Layer TCP": {
        "Source Port": " 41602",
        "Destination Port": " 443",
        "Stream index": " 0",
        "Conversation completeness": " Incomplete (0)",
        "TCP Segment Len": " 0",
        "Sequence Number": " 1    (relative sequence number)",
        "Sequence Number (raw)": " 3621103561",
        "Next Sequence Number": " 1    (relative sequence number)",
        "Acknowledgment Number": " 1    (relative ack number)",
        "Acknowledgment number (raw)": " 477468593",
        "0101 .... ": " Header Length: 20 bytes (5)",
        "Flags": " 0x010 (ACK)",
        "000. .... .... ": " Reserved: Not set",
        "...0 .... .... ": " Nonce: Not set",
        ".... 0... .... ": " Congestion Window Reduced (CWR): Not set",
        ".... .0.. .... ": " ECN-Echo: Not set",
        ".... ..0. .... ": " Urgent: Not set",
        ".... ...1 .... ": " Acknowledgment: Set",
        ".... .... 0... ": " Push: Not set",
        ".... .... .0.. ": " Reset: Not set",
        ".... .... ..0. ": " Syn: Not set",
        ".... .... ...0 ": " Fin: Not set",
        "TCP Flags": " \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7A\u00b7\u00b7\u00b7\u00b7",
        "Window": " 65535",
        "Calculated window size": " 65535",
        "Window size scaling factor": " -1 (unknown)",
        "Checksum": " 0xf70a [unverified]",
        "Checksum Status": " Unverified",
        "Urgent Pointer": " 0",
        "Timestamp": "Timestamps",
        "Time since first frame in this TCP stream": " 0.000000000 seconds",
        "Time since previous frame in this TCP stream": " 0.000000000 seconds"
    }
}

</pre>

## 🔍 IDS Detect Algorithm 분석

**패킷이 캡쳐된 결과를 기반으로 강력한 문자열 탐지기능을 지원합니다.**

any any - any any [layer : tcp] [flags : fin] [msg : 스텔스 스캔 탐지]  
모든 tcp 트래픽의 flag가 fin인 패킷을 탐지 시 "스텔스 스캔 탐지" 출력.  

any any - any any [layer : tcp] [content : hi] [msg : server hi 감지]  
모든 tcp 트래픽의 데이터 안에 hi라는 문자열 포함 시 "server hi 감지" 출력.  

예시로 적힌 탐지 규칙을 패킷에 일치하기 쉽게 변환을 해주고 메모리에 저장을 합니다.

IP : any -> 0.0.0.0
Port : any -> None

option -> key, value

<pre>
def init_memory():
    rule_memory.memory = []

    with open(f'{USER_PATH}/data/offensive/rule', 'r', encoding='utf-8') as f:
        rules = f.read().split("\n")
        if rules[0] == "":
            print("return")
            return
    ll = []
    try:
        for rule in rules:
            info = rule.split(" ")[:6]
            flag ,src_ip, src_port, target, des_ip, des_port = info
            src_ip = "0.0.0.0" if src_ip == "any" else src_ip
            des_ip = "0.0.0.0" if des_ip == "any" else des_ip
            src_port = None if src_port == "any" else int(src_port)
            des_port = None if des_port == "any" else int(des_port)
            ll = [flag ,src_ip, src_port, target, des_ip, des_port]
            matches = re.findall(r"\[[^\]]*\]", rule)

            for layer in matches:
                layer = layer.replace("[", "").replace("]", " ")
                if "msg" not in layer:
                    layer = layer.lower().split(":")
                else:
                    msg = layer.split(":")[1].rstrip()
                    continue
                if "layer" in layer[0]:
                    p = layer[1].replace(" ", "").upper()
                    ll.append(f"Layer {p}")

                elif "protocol" in layer[0]:
                    p = layer[1].upper().replace(" ", "")
                    ll.append(f"Layer {p}")

                elif "flag" in layer[0]:
                    ll.append(["Flags", layer[1].upper()])

                elif "conent" in layer[0]:
                    ll.append(["Content", layer[1].upper()])

                else:
                    ll.append([layer[0].strip().title(),layer[1].strip()])

            ll.append(msg)
            ll.append(rule)

            rule_memory.memory.append(ll)
    except ValueError as e:
        return
</pre>

규칙이 여러 개일 경우 순차적으로 규칙 데이터를 기반으로 탐지를 시작합니다.  
<pre>

def detective_opensive(data, func):
    packet = json.loads(data)
    layer_key = list(packet.keys())[1]

    #3계층 이상
    if layer_key == "Layer IP":
        sip = packet["Layer IP"]["Source Address"].strip()
        dip = packet["Layer IP"]["Destination Address"].strip()
        protocol = packet["Layer IP"]["Protocol"][1:4].strip()
        sport = int(packet[f"Layer {protocol}"]["Source Port"].strip())
        dport = int(packet[f"Layer {protocol}"][ "Destination Port"].strip())
    
    else: #2계층 이하
        for key, value in packet[layer_key].items():
            skey = key.lower()
            if ("sender ip" in skey) or ("source" in skey):
                sip = packet[layer_key][key]
            elif("taget" in skey) or ("destination" in skey):
                dip = packet[layer_key][key]
            sport = None
            dport = None
</pre>

먼저 패킷이 2계층, 3계층 이상의 데이터를 분류를 하여  
Source와 Destination의 주소를 구분합니다.

option : value들을 각각 key와 value로 변환을 해줍니다.

<pre>

    for rules in rule_memory.memory:
        detect = None
        flag, Dsip, Dsport, target, Ddip, Ddport, layer = rules[:7]
        msg, raw_input = rules[-2:]
        #check sip
        if not ((sip == Dsip) or (Dsip == "0.0.0.0")):
            continue
        
        #check dip
        if not ((dip == Ddip) or (Ddip == "0.0.0.0")):
            continue
        
        #check sport
        if not ((sport == Dsport) or (Dsport == None)):
            continue
        
        #check dport
        if not ((dport == Ddport) or (Ddport == None)):
            continue
</pre>
규칙에 적인 IP와 port  
패킷에 적인 IP와 Port가 일치하는지 검사를 합니다.  

단 0.0.0.0일 경우 매칭하지 않음.  

<pre>
        #프로토콜만 지정
        if(len(rules[6:len(rules)-2]) == 1):
            if "Layer" in layer:
                try:
                    packet[layer]
                    detect = True
                except KeyError:
                    detect = False
</pre>

any any - any 23 [protocol : tcp]  
예시와 같이 protocol 또는 layer만 지정해 줬을 시  
해당 layer가 맞는지 검사를 하여 detect 트리거를 통해   
탐지 결과를 반환합니다.  


<pre>

        #레이어에 옵션까지 있을 경우
        #content 부터 시작할 경우
        if "Content" in layer:
            for option in rules[6:len(rules)-2]:
                detect = False
                if not "Content" in option[0]:
                    print("너무 많은 인수 ")
                    break
                Mvalue = option[1]
                for key in packet.keys():
                    for obj, objvalue in packet[key].items():
                        if Mvalue.lower() in objvalue.lower():
                            detect = True
<pre>

첫번쨰 옵션이 layer 또는 protocol이 아닌 content일 경우 완전 탐색을 하여   
content의 값이 들어 있는지 검사를 진행합니다.  
detect 트리거를 통해 탐지 결과 반환합니다.  

</pre>

        #레이어를 지정했을 경우 시작할 경우
        else:
            try:
                for option in rules[7:len(rules)-2]:
                    detect = False
                    if "Layer" in option:
                        layer = option
                    else:
                        Mkey, Mvalue = option
                        Mkey = Mkey.strip().title()
                        Mvalue = Mvalue.strip()

                        if not Mkey == "Content":
                            val = packet[layer][Mkey]
                            if Mvalue in val:
                                detect = True
                        else:
                            for obj, obvalue in packet[layer].items():
                                if Mvalue in obvalue:
                                    detect = True
                    if not detect:
                        break
            except KeyError as e:
                print("불일치!", e)
</pre>
첫번쨰 옵션이 Protocol과 두번 쨰 옵션이 매칭 데이터 일 경우
hash화를 통한 데이터 검색을 이용하여 데이터가 있는지 판단을 합니다.

또한 매칭 데이터가 아닌 Content일 경우 해당 레이어 안에 있는  
값에 대한 완전 탐색을 진행합니다.  

<pre>
        #Detect, Drop, Detect-Drop
        if detect:
            time = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            """data = {
                "time" : time,
                "Type" : Type,
                "msg" : msg,
                "user" : user,
                "value" : value
            }"""
            if flag == "Detect":
                send_msg = f"{time}\nDetect!\nrule: {raw_input}\nsrc_ip: {sip}\nsrc_port: {sport}\ndst_ip: {dip}\ndst_port: {dport}"
                func(time, flag, msg, "System", send_msg)

            elif flag == "Drop":
                send_msg = f"{time}\nBlock!\nrule: {raw_input}\nsrc_ip: {sip}\nsrc_port: {sport}\ndst_ip: {dip}\ndst_port: {dport}"
                func(time, flag, msg, "System", send_msg)
                #f"iptables -A INPUT -s {sip} -j DROP"
                #f"iptables -A PREROUTING -s {sip} -j DROP"

            elif flag == "Detect-Drop":
                pass

            else:
                msg = "error"
</pre>
끝으로 detect가 True일경우 탐지가 된 것으로 판단하여
flag에 있는 값을 통하여, 탐지 또는 차단을 수행하게 됩니다.


이상 Hash와 완전탐색 알고리즘을 이용한 IDS 탐지 알고리즘 분석이었습니다.  
감사합니다.  

Date : 2025-05-28 Wed