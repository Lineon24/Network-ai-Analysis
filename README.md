# 🧠 AION - AI Analysis Server
> **XGBoost 기반 AI 네트워크 침입 탐지 시스템 (AI-based NIDS Analysis Server)**

**AION AI Server**는 분석기가 보낸 **5초 단위 트래픽 통계와 41개 특징**을 이용해 정상 트래픽과 7개 공격 유형을 분류하는 FastAPI·XGBoost 기반 분석 서버입니다.
자체 구축한 전체 데이터 30,475건 중 **테스트셋 6,095건에서 정확도 100%**를 기록했습니다. 이는 해당 자체 테스트셋의 평가 결과이며, 실제 운영 환경에서 오탐이 없다는 의미는 아닙니다.

## 담당 범위

저는 AION의 3인 팀에서 팀장을 맡아 데이터 수집기, 자체 데이터셋, 공격 탐지 모델과 이 분석 서버를 개발했습니다. 분석기·AI 서버·웹 서버의 역할과 JSON 인터페이스, API 인증 알고리즘을 설계하고 초기 웹 와이어프레임을 구성했습니다.

웹사이트와 웹 측 인증·데이터 관리·시각화는 서승진이, 분석기 고도화·위험 IP 식별·GUI·매뉴얼은 김윤정이 담당했습니다. 이 저장소에서는 제가 담당한 측정·모델링·분석 서버의 기술적 판단과 구현을 설명합니다. 팀의 서비스 화면과 시연은 [AION 서비스 개요](https://github.com/Lineon24/AION-NIDS-Service)에서 확인할 수 있습니다.

---

## 🎥 Server Demo (실시간 탐지 시연)
분석기에서 데이터를 보내 AI 서버가 트래픽 데이터를 수신하고, 전처리 및 추론을 거쳐 위협을 판별하는 실시간 로그 화면입니다.

<div align="center">
  <img src="https://github.com/Lineon24/AION-NIDS-Service/blob/main/images/%EA%B3%B5%EA%B2%A9%20%ED%83%90%EC%A7%80%201.gif" width="100%">
  <br/><br/>
  <b>[Process Pipeline]</b><br/>
  📡 요청 인증 ➔ 🧩 41개 특징 형식·순서 정리 ➔ 🤖 XGBoost 예측 ➔ ⚠️ 결과 전달 및 반환
</div>

---

## 🔬 R&D Methodology (연구 방법론)

### 1. 정상 트래픽을 공격으로 판단하는 문제

초기에는 CIC-DDoS 2019, CSE-CIC-IDS 2018, CIC-IDS 2017을 활용해 모델을 만들었습니다. 정상 트래픽을 DDoS로 판단하는 오류가 반복돼 입력 특징을 제거·추가하고 전처리도 바꿨지만 문제가 지속됐습니다.

모델 설정만 조정하기보다, 서비스에서 측정하는 입력이 공격의 행위를 충분히 표현하는지 다시 살펴봤습니다. 보안 도메인을 조사하면서 DDoS의 요청량과 집중 양상을 일정 시간 구간에서 함께 관측하는 방향으로 바꿨습니다.

### 2. 5초 통계와 자체 데이터셋으로 측정 기준 통일

플로우·패킷·바이트 수, TCP·UDP·ICMP 비율, SYN 비율, 증폭 공격 관련 포트 요청량을 **5초 단위로 집계**하도록 설계했습니다. 새 측정 방식은 기존 데이터셋의 입력과 그대로 일치하지 않아, 직접 관리하는 컴퓨터·가상 환경에서 정상·공격 트래픽을 발생시키고 자체 수집기로 데이터를 구축했습니다.

핵심은 학습 데이터와 서비스 분석기가 같은 정의의 특징을 사용하도록 맞추는 것이었습니다. 이 판단은 AION의 입력 환경과 목표 공격에 맞춘 선택이며, 공개 데이터셋이나 플로우 기반 탐지가 일반적으로 부적합하다는 결론은 아닙니다. 5초가 모든 환경에서 최적이라는 비교 실험까지 수행한 것은 아닙니다.

### 3. 공격 행위를 특징으로 옮기며 탐지 범위 확장

초기 DDoS 모델 이후 Slowloris와 Port Scan을 추가했습니다. 분류 이름만 늘리지 않고, 각 공격을 구별할 관측값부터 보완했습니다.

| 대상 | 주목한 행위 | 반영한 측정 관점 |
| --- | --- | --- |
| DDoS·Flood | 트래픽의 양과 프로토콜별 집중 | 플로우·패킷·바이트 수, 프로토콜·SYN 비율, 관련 포트 요청량 |
| Slowloris | 연결을 오래 유지하는 행위 | 연결 지속 시간 관련 특징 |
| Port Scan | 여러 목적지 포트에 접근하는 행위 | IP·포트 다양성 관련 특징 |

새 특징을 수집기에 반영하고 데이터를 확보한 뒤 모델과 분석 서버의 입력을 맞췄습니다. 이후에도 남은 오분류는 개별 표본과 수집 환경까지 추적해 정제했습니다.

## 🧬 41 Key Features Description (특징 설계 및 선정 이유)

AION은 **5초(Time-Window)** 동안 집계된 트래픽 통계를 바탕으로, 아래 6가지 카테고리의 41개 특징을 사용하여 공격을 탐지합니다.

아래 탐지 대상은 특징을 설계할 때 참고한 행위와 해석입니다. 개별 특징만으로 공격을 확정하거나 표의 모든 공격 유형을 별도 클래스로 검증했다는 뜻은 아닙니다. 정확한 입력 이름과 순서는 [EXPECTED_FEATURE_LIST](./api/app.py)를 기준으로 합니다.

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
| `src_ip_nunique` | 고유 출발지 IP 개수 | 출발지 분산 정도 |
| `src_ip_entropy` | 출발지 IP 분포의 엔트로피 | 출발지 집중·분산 양상 |
| `dst_ip_nunique` | 고유 목적지 IP 개수 | 목적지 집중 정도 |
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
| `src_proto_bitmask_max_popcount` | 프로토콜 비트마스크에 포함된 종류 수 관련 최댓값 | **Protocol Mix** |
| `src_proto_multi_protocol_fraction` | 여러 프로토콜을 사용하는 출발지 관련 비율 | **Protocol Mix** |

---

## 🛡️ Security Architecture (보안 기술)

### Hash & Salt 기반 API 인증
웹에서 키를 발급받아 분석기에 등록하고, 분석 서버가 요청을 검증하는 흐름을 설계했습니다. API 키 원문을 DB에 보관하지 않고 서버 비밀값을 분리해 관리하는 구조입니다.

1. **DB 조회:** 요청 헤더의 `auth-key`로 `api_keys` 테이블의 `random_value`와 `status`를 조회합니다.
2. **활성 상태 확인:** 키가 `active` 상태인지 확인합니다.
3. **해시 검증:** `SHA-256(random_value + API_KEY_SALT)`를 계산해 요청의 `api-key`와 비교합니다. `API_KEY_SALT`는 서버 환경변수입니다.
4. **오류 구분:** 유효하지 않은 인증·비활성 키는 HTTP 403, 서버 비밀값 누락은 HTTP 500으로 처리합니다.

인증 대상은 키를 가진 클라이언트의 요청입니다. 하드웨어 기반 기기 귀속이나 키 복제 방지는 구현 범위에 포함하지 않습니다. 현재 코드에는 Supabase 초기화 실패 시 개발용 인증값을 반환하는 분기가 남아 있어, 운영 전에는 DB 장애 시 요청을 거절하도록 보완해야 합니다.

### 분석 서버의 입력·추론·결과 전달

[api/app.py](./api/app.py)의 `POST /predict`는 인증을 통과한 요청에 다음 처리를 수행합니다.

```text
분석기의 5초 통계 특징
  → 요청 인증
  → EXPECTED_FEATURE_LIST의 41개 열 순서로 입력 정리
  → 결측값·무한값 처리
  → XGBoost predict_proba 및 라벨 변환
  → 공격 유형·카테고리·UTC 시각·클래스별 점수 구성
  ├─ FORWARD_URL이 있으면 웹 서버에 JSON 전달 시도
  └─ 분석기에 결과 반환
```

- **입력 계약:** 리스트는 41개 길이를 확인하고, 딕셔너리는 특징 이름 순서로 값을 가져옵니다. 딕셔너리의 누락값·수치 변환 실패값과 결측값·무한값은 0으로 처리합니다. `normalize_features`는 통계적 표준화가 아닌 입력 형식 정리입니다.
- **판정 참고값:** 주요 입력을 `key_features_evidence`로 묶어 결과와 전달합니다. SHAP 기반 개별 설명이나 인과 설명은 아니며, `confidence`도 실제 정확도가 아닌 모델 출력 점수입니다.
- **외부 전송:** HTTPX의 10초 타임아웃과 전송 예외 로그를 두고, 예외가 발생해도 분석기에 결과를 반환합니다. 전송을 기다리는 구조이며 전송 큐·자동 재전송·HTTP 오류 상태 검사를 통한 저장 보장까지 구현한 것은 아닙니다.

분석기·모델·웹이 같은 특징과 결과를 해석하도록 JSON 인터페이스를 정하는 것이 연동의 핵심이었습니다. 분석기의 임계치 기반 위험 IP 후보 식별은 이 서버의 통계 특징 기반 공격 유형 분류와 별도 역할입니다.

---

## 📉 Research & Optimization (연구 및 최적화 과정)

전체 정확도가 높더라도 틀린 표본을 따로 확인했습니다. 오분류가 발생한 수집 환경을 추적하면서, 공격이 실행되는 동안 수집됐다는 사실과 각 관측값이 공격 행위 자체를 나타낸다는 사실을 구분해야 한다는 점을 확인했습니다.

### 1. Model Iteration (모델 고도화 과정)

#### 🛑 1차 모델 (v1.0) - Accuracy 99.97%
* **학습 데이터:** 총 30,202개
* **문제점 발견:** 전체적인 정확도는 높았으나, **반사(Reflection) 트래픽**을 공격 트래픽(UDP_Flood, UDP_Amplify)으로 오인하는 **False Positive(오탐)** 현상이 일부 발생했습니다.
* **원인 분석:** 수집 환경에서 피해자 측 응답·반사 트래픽이 공격 데이터에 섞여 모델 판단에 영향을 주는 것을 확인했습니다. 공격 트래픽과 피해자 측 트래픽의 의미를 구분하고 라벨·데이터 구성을 정리했습니다.
* **평가 범위:** 보고서 1차 테스트셋 6,041건 중 2건을 오분류했습니다. 이 평가에는 Slowloris·Port Scan이 포함돼 있으며 초기 DDoS 전용 모델의 평가와 구분합니다.

#### ✅ 2차 모델 (v2.0 / Final) - Accuracy 100.00%
* **해결 방안:**
    1. **Data Augmentation:** 반사(Reflection) 관련 정상 트래픽 데이터를 약 **300개 추가 수집**하여 학습셋에 포함.
    2. **Noise Reduction:** 모델 판단을 흐리는 노이즈 데이터를 제거 및 재라벨링.
* **최종 결과:** 전체 데이터 **30,475건 중 테스트셋 6,095건**에서 정확도 100%, 클래스별 **Precision·Recall·F1-score 1.00**을 기록했습니다.

두 평가의 데이터 구성이 달라 동일 조건의 성능 향상률로 계산하지 않습니다. 다른 수집 시점·환경의 트래픽, 새로운 공격 패턴과 학습·평가 데이터의 독립성을 추가로 검증해야 합니다. 이 저장소의 수치는 자체 테스트셋의 결과입니다.

| Class | precision | recall | f1-score | support |
| :--- | :---: | :---: | :---: | :---: |
| **BENIGN** | 1.00 | 1.00 | 1.00 | 2680 |
| **ICMP_FLOOD** | 1.00 | 1.00 | 1.00 | 508 |
| **OTHER_TCP_FLOOD** | 1.00 | 1.00 | 1.00 | 482 |
| **Port_Scan** | 1.00 | 1.00 | 1.00 | 506 |
| **SYN_FLOOD** | 1.00 | 1.00 | 1.00 | 513 |
| **Slowloris_Attack** | 1.00 | 1.00 | 1.00 | 208 |
| **UDP_AMPLIFY** | 1.00 | 1.00 | 1.00 | 524 |
| **UDP_FLOOD** | 1.00 | 1.00 | 1.00 | 674 |
| | | | | |
| **accuracy** | | | **1.00** | **6095** |
| **macro avg** | 1.00 | 1.00 | 1.00 | 6095 |
| **weighted avg** | 1.00 | 1.00 | 1.00 | 6095 |

### 2. Confusion Matrix (혼동 행렬)
최종 자체 테스트셋 6,095건의 예측과 라벨이 일치한 평가 기록입니다. 해당 표본에서 오분류가 0건이었다는 의미이며, 실운영의 오탐·미탐이 없음을 보장하지 않습니다.

<div align="center"> <img src="https://github.com/Lineon24/AION-NIDS-Service/blob/main/images/confusion_matrix.png" width="85%"/>


(X축: 예측 라벨 / Y축: 실제 라벨) </div>


### 3. Feature Importance (XGBoost 특징 중요도)
41개의 특징 중 AI 모델이 공격을 판단하는 데 가장 중요하게 사용한 특징 순서들 입니다.

<div align="center"> <img src="https://github.com/Lineon24/AION-NIDS-Service/blob/main/images/feature_importance_all.png" width="85%" /> </div>

Top 3 Features:

tcp_ratio: TCP 프로토콜 기반 공격(SYN Flood 등) 판별에 핵심.

syn_flag_ratio: 정상 트래픽과 SYN Flood를 구분하는 결정적 지표.

avg_flow_duration: 지속 시간이 긴 Slowloris 공격 탐지에 기여.

특징 중요도는 학습된 모델이 어떤 입력을 주로 사용했는지 확인하는 자료입니다. 프로토콜·플래그·지속 시간에 주목한 설계를 해석하는 데 참고했으며, 개별 특징의 인과관계나 다른 환경의 탐지 성능을 증명하지는 않습니다.

## 🛠️ Tech Stack & Setup

| 분류 | 기술 |
| :--- | :--- |
| **Core** | ![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white) |
| **Framework** | ![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white) ![Uvicorn](https://img.shields.io/badge/Uvicorn-ASN-499848?logo=gunicorn&logoColor=white) |
| **AI Engine** | ![XGBoost](https://img.shields.io/badge/XGBoost-Models-FLAT.svg?logo=xgboost) ![Pandas](https://img.shields.io/badge/Pandas-Data-150458?logo=pandas&logoColor=white) |
| **Infra** | ![Supabase](https://img.shields.io/badge/Supabase-DB-3ECF8E?logo=supabase&logoColor=white) |

