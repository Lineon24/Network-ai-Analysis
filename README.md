# 🧠 AION - AI Analysis Server
> **XGBoost 기반 AI 네트워크 침입 탐지 시스템 (AI-based NIDS Analysis Server)**

**AION AI Server**는 클라이언트(분석기)로부터 수신한 트래픽 통계 데이터를 분석하여, 7가지 이상의 네트워크 위협을 실시간으로 판별하는 시스템의 핵심 엔진입니다.
기존 공개 데이터셋의 한계를 극복하기 위해 **자체 구축한 데이터셋**과 **독자 설계된 41개 특징**를 기반으로 **100%의 탐지 정확도**를 달성했습니다.

---

## 🎥 Server Demo (실시간 탐지 시연)
분석기에서 데이터를 보내 AI 서버가 트래픽 데이터를 수신하고, 전처리 및 추론을 거쳐 위협을 판별하는 실시간 로그 화면입니다.

<div align="center">
  <img src="https://github.com/Lineon24/AION-NIDS-Service/blob/main/images/%EA%B3%B5%EA%B2%A9%20%ED%83%90%EC%A7%80%201.gif" width="100%">
  <br/><br/>
  <b>[Process Pipeline]</b><br/>
  📡 Request 수신 ➔ 🧩 41개 특징 정규화 ➔ 🤖 XGBoost 예측 ➔ ⚠️ 결과 반환 (예: UDP_Amplify)
</div>

---

## 🔬 R&D Methodology (연구 방법론)

### 1. 데이터셋 연구 및 차별점 (vs CIC-IDS2017)
저는 **CIC-IDS2017, CSE-CIC-IDS2018** 등 기존 NIDS 데이터셋을 심층 분석하였습니다.
그러나 기존의 **단일 플로우(Single-flow)** 분석 방식은 실제 환경의 대규모 DDoS나 지능형 저속 공격(Slowloris)을 탐지하는 데 한계가 있음을 확인했습니다.

💡 **AION의 해결책: '5초 단위 플로우 통계 (5-sec Flow Aggregation)'**
기존의 탐지 방식이 단일 플로우(Single-flow)라는 '나무' 만 분석했다면, 저희는 네트워크 전반의 흐름이라는 '숲' 을 분석합니다. 이를 통해 개별 패킷에서는 보이지 않던 평상시와 다른 이상 징후(Anomaly) 를 포착해냅니다.
우리는 CIC-IDS2017의 특징 아이디어를 참고하되, 이를 **시간 기반(Time-window) 통계**로 재설계하여 **자체 데이터셋**을 구축했습니다.

## 🧬 41 Key Features Description (특징 설계 및 선정 이유)

AION은 **5초(Time-Window)** 동안 집계된 트래픽 통계를 바탕으로, 아래 6가지 카테고리의 41개 특징을 사용하여 공격을 탐지합니다.

### 1. 📊 Volume & Traffic Basics (3 Features)
**[선정 이유]** Flood 공격 발생 시 트래픽 총량이 급증하는 현상을 탐지하기 위함입니다.

| Feature Name | Description (역할) | Detects |
| :--- | :--- | :--- |
| `flow_count` | 5초 동안 발생한 총 플로우(Flow) 개수 | **All Floods** (트래픽 폭주 감지) |
| `packet_count_sum` | 5초 동안 전송된 총 패킷 수의 합 | **DDoS** (대량 패킷 유입) |
| `byte_count_sum` | 5초 동안 전송된 총 바이트(Byte) 수의 합 | **Bandwidth Exhaustion** (대역폭 고갈 공격) |

### 2. 🎯 Protocol & Flags Ratios (5 Features)
**[선정 이유]** 특정 프로토콜이나 플래그가 비정상적으로 높은 비율을 차지하는 것을 식별합니다.

| Feature Name | Description (역할) | Detects |
| :--- | :--- | :--- |
| `syn_flag_ratio` | 전체 패킷 중 SYN 플래그 패킷의 비율 (정상은 낮음) | **SYN Flood** (비율이 1.0에 근접) |
| `tcp_ratio` | 전체 트래픽 중 TCP 프로토콜 비율 | **TCP Flood** |
| `udp_ratio` | 전체 트래픽 중 UDP 프로토콜 비율 | **UDP Flood / Amplify** |
| `icmp_ratio` | 전체 트래픽 중 ICMP 프로토콜 비율 | **ICMP Flood** |
| `fwd_bwd_pkt_ratio` | 송신(Fwd) 대 수신(Bwd) 패킷 비율 | **DoS** (응답 없는 일방적 요청) |

### 3. 🌐 IP/Port Diversity & Entropy (9 Features)
**[선정 이유]** 공격자가 '분산(Distributed)'되어 있는지 '집중(Scan)'되어 있는지 수학적(Entropy)으로 구분합니다.

| Feature Name | Description (역할) | Detects |
| :--- | :--- | :--- |
| `src_ip_nunique` | 고유 출발지 IP 개수 (공격자 수) | **DDoS** (값이 매우 높음) |
| `src_ip_entropy` | 출발지 IP의 무작위성 (난수화 여부) | **DDoS** (IP 스푸핑 탐지) |
| `dst_ip_nunique` | 고유 목적지 IP 개수 (피해자 수) | **DDoS** (보통 1개 집중) |
| `dst_port_nunique` | 고유 목적지 포트 개수 | **Port Scan** (값이 매우 높음) |
| `dst_port_entropy` | 목적지 포트의 무작위성 | **Port Scan** (무작위 포트 스캔) |
| `top_dst_port_1` | 가장 많이 접속된 포트 번호 | **Service Targeting** (예: 80번 집중) |
| `top_dst_port_1_hits` | 1위 포트의 접속 횟수 | **Specific Service Flood** |
| `top_src_count` | 가장 많이 접속한 상위 IP의 요청 수 | **Single IP DoS** |
| `max_dst_persist` | 특정 목적지로의 지속적인 연결 강도 | **Persistence Attack** |

### 4. 📣 UDP Amplification Ports (9 Features)
**[선정 이유]** 반사 공격(Reflection)에 악용되는 특정 UDP 포트들의 트래픽 양을 감시합니다.

| Feature Name | Target Service (Port) | Detects |
| :--- | :--- | :--- |
| `udp_port_53_hit_sum` | DNS (53) | **DNS Amplification** |
| `udp_port_123_hit_sum` | NTP (123) | **NTP Amplification** |
| `udp_port_1900_hit_sum` | SSDP (1900) | **SSDP Reflection** |
| `udp_port_111_hit_sum` | RPC (111) | **RPC Reflection** |
| `udp_port_69_hit_sum` | TFTP (69) | **TFTP Reflection** |
| `udp_port_137_hit_sum` | NetBIOS (137) | **NetBIOS Reflection** |
| `udp_port_161_hit_sum` | SNMP (161) | **SNMP Reflection** |
| `udp_port_389_hit_sum` | CLDAP (389) | **CLDAP Reflection** |
| `udp_port_1434_hit_sum` | MS-SQL (1434) | **MS-SQL Reflection** |

### 5. ⏳ Time & Packet Size Dynamics (7 Features)
**[선정 이유]** 트래픽 양은 적지만 시간을 끄는(Slow) 공격이나, 기계적인(Fixed Size) 공격 패턴을 탐지합니다.

| Feature Name | Description (역할) | Detects |
| :--- | :--- | :--- |
| `avg_flow_duration` | 플로우의 평균 지속 시간 | **Slowloris** (매우 긺) |
| `flow_iat_mean_mean` | 패킷 도착 간격(IAT)의 평균 | **Slow-Rate Attack** |
| `flow_iat_std_mean` | 패킷 도착 간격의 표준편차 | **Automated Tool** (일정 간격) |
| `flow_pkt_size_mean` | 패킷 크기 평균 | **Slowloris** (매우 작음) |
| `flow_pkt_size_median` | 패킷 크기 중앙값 | **Malware C&C** |
| `flow_pkt_size_std` | 패킷 크기 표준편차 | **Flooding Tool** (크기가 일정함) |
| `flow_pkt_size_max` | 패킷 크기 최댓값 | **Packet Anomalies** |

### 6. 🚀 Flow Creation Rate & Protocol Mix (8 Features)
**[선정 이유]** 플로우 생성 속도(Rate)와 비정상적인 프로토콜 조합을 분석합니다.

| Feature Name | Description (역할) | Detects |
| :--- | :--- | :--- |
| `flow_start_rate` | 초당 플로우 시작 횟수 | **Explosive Flooding** |
| `fsr_mean`, `fsr_std`, `fsr_max` | 플로우 시작 속도의 통계적 변화 | **Burst Attacks** |
| `fsr_rate_increase` | 플로우 시작 속도 증가율 | **Flash Crowd vs DDoS** |
| `src_proto_bitmask_nunique` | 사용된 프로토콜 조합의 다양성 | **Advanced Scanning** |
| `src_proto_bitmask_max` | 가장 많이 쓰인 프로토콜 조합 | **Protocol Anomaly** |
| `src_proto_multi...` | 다중 프로토콜 사용 비율 | **Complex Attacks** |

---

## 🛡️ Security Architecture (보안 기술)

### Hash & Salt 기반 API 인증
본 서버는 데이터베이스에 API 키 원문을 저장하지 않는 **Secure Auth Architecture**를 적용했습니다.

1. **DB 저장:** 사용자별 `Auth-Key`와 난수화된 `Random Value`만 저장.
2. **검증 로직:** 클라이언트 요청 시, 서버는 `Hash(Random Value + Admin Value)`를 계산하여 검증.
3. **효과:** DB가 탈취되더라도 해커는 실제 API 키를 복구할 수 없습니다.

---

## 📉 Research & Optimization (연구 및 최적화 과정)

본 프로젝트는 단 한 번의 학습으로 끝나지 않고, **오탐(False Positive) 분석과 데이터셋 정제**를 통해 모델 성능을 극한으로 끌어올렸습니다.

### 1. Model Iteration (모델 고도화 과정)

#### 🛑 1차 모델 (v1.0) - Accuracy 99.97%
* **학습 데이터:** 총 30,202개
* **문제점 발견:** 전체적인 정확도는 높았으나, **반사(Reflection) 트래픽**을 공격 트래픽(UDP_Flood, UDP_Amplify)으로 오인하는 **False Positive(오탐)** 현상이 일부 발생했습니다.
* **원인 분석:** 정상적인 통신 과정에서 발생하는 반사 패킷과 실제 공격 패킷 간의 미세한 패턴 차이를 학습하기에 데이터가 부족했습니다.

#### ✅ 2차 모델 (v2.0 / Final) - Accuracy 100.00%
* **해결 방안:**
    1. **Data Augmentation:** 반사(Reflection) 관련 정상 트래픽 데이터를 약 **300개 추가 수집**하여 학습셋에 포함.
    2. **Noise Reduction:** 모델 판단을 흐리는 노이즈 데이터를 제거 및 재라벨링.
* **최종 결과:** 총 30,475개 데이터를 대상으로 테스트한 결과, 모든 공격 유형에 대해 **Precision, Recall, F1-Score 1.00**을 달성했습니다.

| Class | precision | recall | f1-score | support |
| :--- | :---: | :---: | :---: | :---: |
| **BENIGN** | 1.00 | 1.00 | 1.00 | 2680 |
| **ICMP_FLOOD** | 1.00 | 1.00 | 1.00 | 508 |
| **OTHER_TCP_FLOOD** | 1.00 | 1.00 | 1.00 | 482 |
| **Port_Scan** | 1.00 | 1.00 | 1.00 | 506 |
| **SYN_FLOOD** | 1.00 | 1.00 | 1.00 | 513 |
| **Slowloris_Attack** | 1.00 | 1.00 | 1.00 | 288 |
| **UDP_AMPLIFY** | 1.00 | 1.00 | 1.00 | 524 |
| **UDP_FLOOD** | 1.00 | 1.00 | 1.00 | 674 |
| | | | | |
| **accuracy** | | | **1.00** | **6095** |
| **macro avg** | 1.00 | 1.00 | 1.00 | 6095 |
| **weighted avg** | 1.00 | 1.00 | 1.00 | 6095 |

### 2. Confusion Matrix (혼동 행렬)
최종 모델이 예측한 결과와 실제 라벨이 완벽하게 일치함을 보여주는 혼동 행렬입니다. 대각선(정답)에 모든 숫자가 위치하며, 잘못 예측한 건수(오탐)가 **'0'**임을 확인할 수 있습니다.

<div align="center"> <img src="https://github.com/Lineon24/AION-NIDS-Service/blob/main/images/confusion_matrix.png" width="85%"/>


(X축: 예측 라벨 / Y축: 실제 라벨) </div>


### 3. Feature Importance (XGBoost 특징 중요도)
41개의 특징 중 AI 모델이 공격을 판단하는 데 가장 중요하게 사용한 특징 순서들 입니다.

<div align="center"> <img src="https://github.com/Lineon24/AION-NIDS-Service/blob/main/images/feature_importance_all.png" width="85%" /> </div>

Top 3 Features:

tcp_ratio: TCP 프로토콜 기반 공격(SYN Flood 등) 판별에 핵심.

syn_flag_ratio: 정상 트래픽과 SYN Flood를 구분하는 결정적 지표.

avg_flow_duration: 지속 시간이 긴 Slowloris 공격 탐지에 기여.

이 분석 결과는 우리가 설계한 특징들이 **실제 공격의 특성(Protocol, Flag, Time)**을 정확히 반영하고 있음을 증명합니다.

## 🛠️ Tech Stack & Setup

| 분류 | 기술 |
| :--- | :--- |
| **Core** | ![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white) |
| **Framework** | ![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white) ![Uvicorn](https://img.shields.io/badge/Uvicorn-ASN-499848?logo=gunicorn&logoColor=white) |
| **AI Engine** | ![XGBoost](https://img.shields.io/badge/XGBoost-Models-FLAT.svg?logo=xgboost) ![Pandas](https://img.shields.io/badge/Pandas-Data-150458?logo=pandas&logoColor=white) |
| **Infra** | ![Supabase](https://img.shields.io/badge/Supabase-DB-3ECF8E?logo=supabase&logoColor=white) |

