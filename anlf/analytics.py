import httpx
from datetime import datetime
from typing import Optional
from shared.config import (
    KSERVE_URL, MODEL_NAME, KSERVE_HOST,
    LINK_CAPACITY_BPS, ANOMALY_SPIKE_RATIO, DEFAULT_WINDOW_MIN
)
from shared.models import Snssai, AnalyticsRequest
from adrf.client import adrf


EXC_LONG_LIVE_LARGE_RATE = "UNEXPECTED_LONG_LIVE_LARGE_RATE_FLOWS"
EXC_DDOS                 = "SUSPICION_OF_DDOS_ATTACK"


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

        abnormal, cause, cause_kind = model_result["is_anomaly"], None, None

        if abnormal:
            if byte_ratio > ANOMALY_SPIKE_RATIO:
                cause      = f"MODEL_FLAGGED + TRAFFIC_SPIKE: {byte_ratio:.1f}x increase in bytes"
                cause_kind = "TRAFFIC_SPIKE"
            elif byte_ratio < (1 / ANOMALY_SPIKE_RATIO) and prev_bytes > 10_000:
                cause      = f"MODEL_FLAGGED + TRAFFIC_DROP: {byte_ratio:.2f}x decrease in bytes"
                cause_kind = "TRAFFIC_DROP"
            elif flow_ratio > ANOMALY_SPIKE_RATIO * 1.5:
                cause      = f"MODEL_FLAGGED + FLOW_SPIKE: {flow_ratio:.1f}x increase in flows"
                cause_kind = "FLOW_SPIKE"
            else:
                cause      = "MODEL_FLAGGED: multivariate anomaly (unusual feature combination)"
                cause_kind = "MODEL_ONLY"
        elif not model_result["reachable"]:
            if byte_ratio > ANOMALY_SPIKE_RATIO:
                abnormal, cause, cause_kind = True, f"FALLBACK_TRAFFIC_SPIKE: {byte_ratio:.1f}x increase", "TRAFFIC_SPIKE"
            elif byte_ratio < (1 / ANOMALY_SPIKE_RATIO) and prev_bytes > 10_000:
                abnormal, cause, cause_kind = True, f"FALLBACK_TRAFFIC_DROP: {byte_ratio:.2f}x decrease", "TRAFFIC_DROP"
            elif flow_ratio > ANOMALY_SPIKE_RATIO * 1.5:
                abnormal, cause, cause_kind = True, f"FALLBACK_FLOW_SPIKE: {flow_ratio:.1f}x increase", "FLOW_SPIKE"

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

        exceptions = []
        if abnormal:
            exceptions.append(self._build_exception(
                cause_kind, byte_ratio, flow_ratio, last_bytes, last_flows, confidence
            ))

        return {
            "analyticsId":       "ABNORMAL_BEHAVIOUR",
            "snssai":            snssai.model_dump(),
            "timeStamp":         datetime.utcnow().isoformat() + "Z",
            "validityPeriod":    f"PT{DEFAULT_WINDOW_MIN}M",
            "exceptions":        exceptions,
            "abnormalBehaviour": abnormal,
            "cause":             cause,
            "confidence":        confidence,
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

    def _build_exception(self, cause_kind: str, byte_ratio: float, flow_ratio: float,
                         last_bytes: int, last_flows: int, confidence: int) -> dict:
        exception_id = {
            "TRAFFIC_SPIKE": EXC_LONG_LIVE_LARGE_RATE,
            "TRAFFIC_DROP":  EXC_LONG_LIVE_LARGE_RATE,
            "FLOW_SPIKE":    EXC_DDOS,
            "MODEL_ONLY":    EXC_LONG_LIVE_LARGE_RATE,
        }.get(cause_kind, EXC_LONG_LIVE_LARGE_RATE)

        if cause_kind == "FLOW_SPIKE":
            exception_level = int(min(100, max(1, flow_ratio * 10)))
        elif cause_kind == "TRAFFIC_DROP":
            exception_level = int(min(100, max(1, (1 / max(byte_ratio, 0.001)) * 5)))
        else:
            exception_level = int(min(100, max(1, byte_ratio * 1.5)))

        if cause_kind == "TRAFFIC_DROP":
            trend = "down"
        elif cause_kind in ("TRAFFIC_SPIKE", "FLOW_SPIKE"):
            trend = "up"
        elif byte_ratio > 1.2:
            trend = "up"
        elif byte_ratio < 0.8:
            trend = "down"
        else:
            trend = "stable"

        return {
            "exceptionId":    exception_id,
            "exceptionLevel": exception_level,
            "exceptionTrend": trend,
            "ratio":          None,
            "amount":         None,
            "supiList":       [],
            "additionalMeasurement": {
                "byteRatio":   round(byte_ratio, 3),
                "flowRatio":   round(flow_ratio, 3),
                "latestBytes": last_bytes,
                "latestFlows": last_flows,
            },
            "confidence":     confidence,
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