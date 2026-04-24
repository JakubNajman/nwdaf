import httpx
from datetime import datetime
from typing import Optional
from shared.config import (
    KSERVE_URL, MODEL_NAME, KSERVE_HOST,
    LINK_CAPACITY_BPS, ANOMALY_SPIKE_RATIO, DEFAULT_WINDOW_MIN
)
from shared.models import Snssai, AnalyticsRequest
from adrf.client import adrf


class AnLF:
    
    def compute_abnormal_behaviour_general(self, req: AnalyticsRequest) -> dict:
        snssai = req.snssaiDnnFilter.snssai if req.snssaiDnnFilter else Snssai()

        raw         = adrf.get_general_anomaly()
        oldest          = raw.get("oldest", {})
        middle          = raw.get("middle",  {})
        latest          = raw.get("latest",  {})

        model_result = self._request_anomaly(latest)

        prev_bytes = middle.get("total_bytes", 1) or 1
        last_bytes = latest.get("total_bytes", 0)
        prev_flows = middle.get("unique_flows", 1) or 1
        last_flows = latest.get("unique_flows", 0)

        byte_ratio = last_bytes / prev_bytes
        flow_ratio = last_flows / prev_flows

        abnormal, cause = model_result["is_anomaly"], None

        if abnormal:
            if byte_ratio > ANOMALY_SPIKE_RATIO:
                cause = f"MODEL_FLAGGED + TRAFFIC_SPIKE: {byte_ratio:.1f}x increase in bytes"
            elif byte_ratio < (1 / ANOMALY_SPIKE_RATIO) and prev_bytes > 10_000:
                cause = f"MODEL_FLAGGED + TRAFFIC_DROP: {byte_ratio:.2f}x decrease in bytes"
            elif flow_ratio > ANOMALY_SPIKE_RATIO * 1.5:
                cause = f"MODEL_FLAGGED + FLOW_SPIKE: {flow_ratio:.1f}x increase in flows"
            else:
                cause = "MODEL_FLAGGED: multivariate anomaly (unusual feature combination)"
        elif not model_result["reachable"]:
            if byte_ratio > ANOMALY_SPIKE_RATIO:
                abnormal, cause = True, f"FALLBACK_TRAFFIC_SPIKE: {byte_ratio:.1f}x increase"
            elif byte_ratio < (1 / ANOMALY_SPIKE_RATIO) and prev_bytes > 10_000:
                abnormal, cause = True, f"FALLBACK_TRAFFIC_DROP: {byte_ratio:.2f}x decrease"
            elif flow_ratio > ANOMALY_SPIKE_RATIO * 1.5:
                abnormal, cause = True, f"FALLBACK_FLOW_SPIKE: {flow_ratio:.1f}x increase"
        
        confidence = 0

        if abnormal and model_result["reachable"]:
            confidence = 90
        elif abnormal and not model_result["reachable"]:
            confidence = 60
        else:
            confidence = 85

        prediction_pretty = ""

        if model_result["prediction"] == 1:
            prediction_pretty = "NORMAL"
        else: prediction_pretty = "ABNORMAL"

        return {
            "analyticsId":       "ABNORMAL_BEHAVIOUR",
            "snssai":            snssai.model_dump(),
            "abnormalBehaviour": abnormal,
            "cause":             cause,
            "confidence":        confidence,
            "timeStamp":         datetime.utcnow().isoformat() + "Z",
            "extraData": {
                "model": {
                    "reachable":     model_result["reachable"],
                    "prediction":    prediction_pretty,
                    "featureVector": model_result["feature_vector"],
                    "error":         model_result["error"],
                },
                "trend": {
                    "oldestBytes": oldest.get("total_bytes", 0),
                    "middleBytes": middle.get("total_bytes", 0),
                    "latestBytes": last_bytes,
                    "byteRatio":   round(byte_ratio, 3),
                    "oldestFlows": oldest.get("unique_flows", 0),
                    "middleFlows": middle.get("unique_flows", 0),
                    "latestFlows": last_flows,
                    "flowRatio":   round(flow_ratio, 3),
                }
            }
        }
    
    def _request_anomaly(self, raw: dict) -> dict:

        total_bytes   = raw.get("total_bytes",   0)
        total_packets = raw.get("total_packets", 0)
        unique_flows  = raw.get("unique_flows",  0)
        src_bytes     = raw.get("src_bytes",     0)
        dst_bytes     = raw.get("dst_bytes",     0)
        avg_bytes     = raw.get("avg_bytes",     0)

        bytes_per_flow   = total_bytes / unique_flows  if unique_flows  > 0 else 0
        bytes_per_packet = total_bytes / total_packets if total_packets > 0 else 0
        src_dst_ratio    = src_bytes   / dst_bytes     if dst_bytes     > 0 else 0

        feature_vector = [
            avg_bytes,
            total_packets,
            unique_flows,
            bytes_per_flow,
            bytes_per_packet,
            src_dst_ratio,
        ]

        try:
            resp = httpx.post(
                f"{KSERVE_URL}/v1/models/{MODEL_NAME}:predict",
                json={"instances": [feature_vector]},
                headers={
                "Content-Type": "application/json",
                "Host": KSERVE_HOST
            },
            timeout=5.0,
            )
            resp.raise_for_status()
            prediction = resp.json()["predictions"][0]
            return {
                "is_anomaly":     prediction == -1,
                "prediction":     int(prediction),
                "feature_vector": feature_vector,
                "reachable":      True,
                "error":          None,
            }
        except Exception as e:
            print(f"[AnLF] KServe unavailable ({e})")
            return {
                "is_anomaly":     False,
                "prediction":     None,
                "feature_vector": feature_vector,
                "reachable":      False,
                "error":          str(e),
            }

    def _parse_period(self, period: Optional[str]) -> int:
            if not period:
                return DEFAULT_WINDOW_MIN
            try:
                return int(period.upper().replace("PT", "").replace("M", ""))
            except ValueError:
                return DEFAULT_WINDOW_MIN


anlf = AnLF()