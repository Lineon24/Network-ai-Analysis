import os
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Header, HTTPException
from pydantic import BaseModel
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from typing import Any
import uvicorn
import hashlib
from supabase import create_client, Client
from datetime import datetime, timezone
from pathlib import Path  

# .env 파일 열기
load_dotenv()

# AI 모델 데이터 가져오기
CURRENT_FILE_PATH = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE_PATH.parent.parent
ARTIFACT_DIR = PROJECT_ROOT / "model_artifacts"
# 데이터 베이스 키 가져오기
ADMIN_SECRET_KEY = os.getenv("API_KEY_SALT")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
# 수파베이스 클라이언트 생성
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
except Exception as e:
    print(f"❌ Supabase 클라이언트 초기화 실패: {e}")
    supabase = None


# 모델 이름 지정
MODEL_FILE_NAME = ARTIFACT_DIR / "ids_model.json"
ENCODER_FILE_NAME = ARTIFACT_DIR / "label_encoder.joblib"

# AI 모델 특징들 교차검증을 위해 추가
EXPECTED_FEATURE_LIST = [
    'src_ip_nunique', 'dst_ip_nunique', 'dst_port_nunique', 'flow_count',
    'packet_count_sum', 'byte_count_sum', 'avg_flow_duration', 'tcp_ratio',
    'udp_ratio', 'icmp_ratio', 'syn_flag_ratio',
    'udp_port_53_hit_sum', 'udp_port_69_hit_sum', 'udp_port_111_hit_sum',
    'udp_port_123_hit_sum', 'udp_port_137_hit_sum', 'udp_port_161_hit_sum',
    'udp_port_389_hit_sum', 'udp_port_1434_hit_sum', 'udp_port_1900_hit_sum',
    'flow_iat_mean_mean', 'flow_iat_std_mean', 'src_ip_entropy',
    'flow_pkt_size_mean', 'flow_pkt_size_median', 'flow_pkt_size_std', 'flow_pkt_size_max',
    'flow_start_rate', 'fsr_mean', 'fsr_std', 'fsr_max', 'fsr_rate_increase',
    'fwd_bwd_pkt_ratio',
    'src_proto_bitmask_nunique', 'src_proto_bitmask_max_popcount', 'src_proto_multi_protocol_fraction',
    'dst_port_entropy', 'top_dst_port_1', 'top_dst_port_1_hits', 'top_src_count',
    'max_dst_persist'
]
EXPECTED_FEATURES = len(EXPECTED_FEATURE_LIST) # 41개의 특징 개수

# 모델 로드 검증
try:
    nids_model = xgb.XGBClassifier()
    nids_model.load_model(str(MODEL_FILE_NAME))
    print(f"✅ NIDS XGBoost 모델 로드 성공: {MODEL_FILE_NAME}")

    # [🌟 수정] 경로 객체를 문자열로 변환하여 load에 전달
    label_encoder = joblib.load(str(ENCODER_FILE_NAME))
    print(f"✅ 레이블 인코더 로드 성공: {ENCODER_FILE_NAME}")
    print(f"✅ 모델이 예측할 클래스: {label_encoder.classes_}")
    print(f"✅ 모델이 기대하는 피처 수: {EXPECTED_FEATURES}")

except FileNotFoundError:
    print(f"❌ 모델({MODEL_FILE_NAME}) 또는 인코더({ENCODER_FILE_NAME}) 파일을 찾을 수 없습니다.")
    raise
except Exception as e:
    print(f"❌ 모델/아티팩트 로드 실패: {e}")
    raise

# FastAPI로 받기 시작
app = FastAPI(
    title="NIDS XGBoost 분석 서버",
    description="5초 단위 통계 피처를 받아 공격/정상 분류 (XGBoost 기반).",
    version="3.0.0"
)

# API 키를 검증하기 위해 인증키를 통해 랜덤 값과 상태 값 가져옴 
async def get_auth_details_from_db(auth_key: str) -> dict | None:
    if not supabase:
        print("WARN: Supabase 클라이언트가 없어 DB 조회를 건너뜁니다.")
        return {"random_value": "DEV_RANDOM_VALUE", "status": "active"}

    try:
        response = supabase.from_("api_keys").select("random_value, status").eq("auth_key", auth_key).single().execute()

        if response.data:
            return response.data

        return None
    except Exception as e:
        print(f"Supabase DB 조회 에러: {e}")
        return None

# 분석 전 해당 함수로 올바른 API 키, 인증 키 인지 검증
async def authenticate_request(
        api_key: str = Header(..., alias="api-key"),
        auth_key: str = Header(..., alias="auth-key")
): 
    # 1. 관리자 키가 env값에 있는지 확인
    if not ADMIN_SECRET_KEY:
        raise HTTPException(status_code=500, detail="서버 설정 오류: ADMIN_SECRET_KEY")
    # 해당 함수로 인증 키 가져옴
    auth_details = await get_auth_details_from_db(auth_key)

    # 2. auth-key 유효성 검사 
    if not auth_details:
        raise HTTPException(status_code=403, detail="인증 실패: 유효하지 않은 auth-key")

    # 3. 2.에서 가져온 상태 값으로 API 키 상태(status) 검사
    if auth_details.get("status") != "active":
        raise HTTPException(status_code=403, detail="API키가 비활성화 상태입니다.")

    # 4. random_value 추출 (status 검사 통과 후)
    random_value = auth_details.get("random_value")

    # 5. 2.에서 가져온 랜덤 값과 1.에서 확인한 관리자 키를 더해 해시 검증 
    server_hash = hashlib.sha256((random_value + ADMIN_SECRET_KEY).encode("utf-8")).hexdigest()
    if server_hash != api_key:
        raise HTTPException(status_code=403, detail="인증 실패: API 키 불일치")

    # 모든 인증 통과
    return auth_details
# 사이트 접속 시 실행 메시지
@app.get("/", summary="Health Check")
def health_check():
    return {
        "status": "ok", 
        "message": "NIDS XGBoost 서버 실행 중", 
        "model": MODEL_FILE_NAME,
        "classes": list(label_encoder.classes_),
        "expected_features_count": EXPECTED_FEATURES
    }

# 들어온 특징 개수가 일치하는지 판단하고 표로 제작
class PredictRequest(BaseModel):
    features: Any  

def normalize_features(input_features):
    if isinstance(input_features, list):
        if len(input_features) != EXPECTED_FEATURES:
            raise ValueError(f"List length mismatch: expected {EXPECTED_FEATURES}, got {len(input_features)}")
        df = pd.DataFrame([input_features], columns=EXPECTED_FEATURE_LIST)
        return df
    
    if isinstance(input_features, dict):
        input_dict = input_features
        row = []
        for name in EXPECTED_FEATURE_LIST:
            val = input_dict.get(name, 0.0) 
            try:
                val_f = float(val)
            except (ValueError, TypeError):
                val_f = 0.0 
            row.append(val_f)
        df = pd.DataFrame([row], columns=EXPECTED_FEATURE_LIST)
        return df
    
    raise ValueError("features 필드는 반드시 list 또는 dict 형태여야 합니다.")

# 특징 받는 부분 authenticate_request 함수 통과 시 작동
@app.post("/predict", summary="실시간 트래픽 피처 분석", dependencies=[Depends(authenticate_request)])
async def predict(request_data: PredictRequest, auth_key: str = Header(..., alias="auth-key")):
    # 모델 추론 부분
    try:
        features_df = normalize_features(request_data.features)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"입력 데이터 처리 오류: {e}")

    features_df = features_df.fillna(0.0).replace([np.inf, -np.inf], 0.0)

    try:
        probabilities = nids_model.predict_proba(features_df)[0]
        predicted_label_index = np.argmax(probabilities) 
        confidence = float(probabilities[predicted_label_index]) * 100.0
        predicted_label_name = label_encoder.inverse_transform([predicted_label_index])[0]
    except Exception as e:
        print(f"❌ 추론 에러: {e}")
        raise HTTPException(status_code=500, detail=f"AI 모델 추론 중 오류 발생: {e}")
    try:
        # features_df.iloc[0] (첫 번째 행)에서 모든 값 추출
        f = features_df.iloc[0]
        # 사용자 반환 값
        key_features = {
            "core_metrics": {
                "flow_count": float(f['flow_count']),
                "packet_count_sum": float(f['packet_count_sum']),
                "byte_count_sum": float(f['byte_count_sum']),
                "flow_start_rate": round(float(f['flow_start_rate']), 2),
                "src_ip_nunique": float(f['src_ip_nunique']),
                "dst_ip_nunique": float(f['dst_ip_nunique']),
                "dst_port_nunique": float(f['dst_port_nunique'])
            },
            "protocol_signals": {
                "syn_flag_ratio": round(float(f['syn_flag_ratio']), 3),
                "tcp_ratio": round(float(f['tcp_ratio']), 3),
                "udp_ratio": round(float(f['udp_ratio']), 3),
                "icmp_ratio": round(float(f['icmp_ratio']), 3),
                "fwd_bwd_pkt_ratio": round(float(f['fwd_bwd_pkt_ratio']), 2),
                # 주요 증폭 포트만 따로 그룹화
            "amplification_ports_hits": {
                # 1. DNS (Port 53)
                "udp_port_DNS(53)_hit_sum": float(f['udp_port_53_hit_sum']),
    
                # 2. NTP (Port 123)
                "udp_port_NTP(123)_hit_sum": float(f['udp_port_123_hit_sum']),
    
                # 3. CLDAP (Port 389)
                "udp_port_CLDAP(389)_hit_sum": float(f['udp_port_389_hit_sum']),
    
                # 4. SSDP (Port 1900)
                "udp_port_SSDP(1900)_hit_sum": float(f['udp_port_1900_hit_sum']),
    
                # 5. SNMP (Port 161)
                "udp_port_SNMP(161)_hit_sum": float(f['udp_port_161_hit_sum']),
    
                # 6. MS-SQL (Port 1434)
                "udp_port_MS_SQL(1434)_hit_sum": float(f['udp_port_1434_hit_sum']),
    
                # 7. NetBIOS (Port 137)
                "udp_port_NetBIOS(137)_hit_sum": float(f['udp_port_137_hit_sum']),
    
                # 8. Portmap/RPC (Port 111)
                "udp_port_Portmap_RPC(111)_hit_sum": float(f['udp_port_111_hit_sum']),
    
                # 9. TFTP (Port 69)
                "udp_port_TFTP(69)_hit_sum": float(f['udp_port_69_hit_sum'])
            }
            },
            "source_analysis": {
                "top_src_count": float(f['top_src_count']),
                "top_dst_port_1": float(f['top_dst_port_1']),
                "top_dst_port_1_hits": float(f['top_dst_port_1_hits']),
                "src_ip_entropy": round(float(f['src_ip_entropy']), 3),
                "src_proto_bitmask_nunique": float(f['src_proto_bitmask_nunique']),
                "src_proto_multi_protocol_fraction": round(float(f['src_proto_multi_protocol_fraction']), 3)
            }
        }
    except Exception as e:
        print(f"WARN: key_features 추출 중 오류: {e}")
        key_features = {}  # 오류 발생 시 비어있는 객체로 대체

        # 결과를 표준 'float()'로 변환 (JSON 직렬화 오류 방지)
    prob_list = [float(round(p * 100, 2)) for p in probabilities]
    LABEL_CATEGORY_MAP = {
    # 1. 정상
    "BENIGN": "정상",
    
    # 2. 디도스
    "ICMP_FLOOD": "디도스",
    "OTHER_TCP_FLOOD": "디도스",
    "SYN_FLOOD": "디도스",
    "UDP_AMPLIFY": "디도스",
    "UDP_FLOOD": "디도스",
    
    # 3. 정찰
    "Port_Scan": "정찰",
    
    # 4. 슬로우 공격
    "Slowloris_Attack": "슬로우 공격"
}
    # 웹 서버 전송 및 사용자 전송 데이터
    results = {
        "auth_key": auth_key,
        "detection_result": predicted_label_name,
        "confidence": f"{confidence:.2f}%",
        "category": LABEL_CATEGORY_MAP.get(predicted_label_name, "기타 공격"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "key_features_evidence": key_features,
        "all_probabilities": dict(zip(label_encoder.classes_, prob_list))
    }
    # 웹서버에 보낼 주소
    forward_url = os.getenv("FORWARD_URL")
    if forward_url:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(forward_url, json=results)
        except Exception as e:
            print(f"WARN: 외부 전송 실패: {e}")

    return results

# --- 개발용 실행 ---
if __name__ == "__main__":
    print("--- NIDS XGBoost 분석 서버 시작 (v3 - 41 features) ---")
    print(f"모델: {MODEL_FILE_NAME}")
    print(f"인코더: {ENCODER_FILE_NAME}")
    print(f"기대 피처 수: {EXPECTED_FEATURES}")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)