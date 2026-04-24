import httpx
import threading
import time
from datetime import datetime
from uuid import uuid4
from shared.models import SubscriptionRequest, AnalyticsRequest, SnssaiDnnFilter, Snssai
from shared.models import AnalyticsId


class SubscriptionManager:

    def __init__(self):
        self._subs = {}
        self._lock = threading.Lock()

    def subscribe(self, req: SubscriptionRequest) -> dict:
        sub_id    = f"sub-{uuid4().hex[:8]}"
        stop_evt  = threading.Event()
        thread    = threading.Thread(
            target=self._notification_loop,
            args=(sub_id, req, stop_evt),
            daemon=True,
            name=f"sub-{sub_id}"
        )
        with self._lock:
            self._subs[sub_id] = {
                "request":    req,
                "thread":     thread,
                "stop_event": stop_evt
            }
        thread.start()
        print(f"[Sub] Created {sub_id} for {req.analyticsId} → {req.notificationUri}")
        return {"subscriptionId": sub_id, "analyticsId": req.analyticsId}

    def update(self, sub_id: str, req: SubscriptionRequest) -> dict:
        with self._lock:
            if sub_id not in self._subs:
                raise KeyError(sub_id)
            self._subs[sub_id]["stop_event"].set()

        stop_evt = threading.Event()
        thread   = threading.Thread(
            target=self._notification_loop,
            args=(sub_id, req, stop_evt),
            daemon=True,
            name=f"sub-{sub_id}"
        )
        with self._lock:
            self._subs[sub_id] = {
                "request":    req,
                "thread":     thread,
                "stop_event": stop_evt
            }
        thread.start()
        print(f"[Sub] Updated {sub_id}")
        return {"subscriptionId": sub_id, "analyticsId": req.analyticsId}

    def unsubscribe(self, sub_id: str):
        with self._lock:
            if sub_id not in self._subs:
                raise KeyError(sub_id)
            self._subs[sub_id]["stop_event"].set()
            del self._subs[sub_id]
        print(f"[Sub] Removed {sub_id}")

    def list_subscriptions(self) -> list:
        with self._lock:
            return [
                {
                    "subscriptionId":  sid,
                    "analyticsId":     s["request"].analyticsId,
                    "notificationUri": s["request"].notificationUri,
                    "repPeriod":       s["request"].eventReportingRequirement.repPeriod
                }
                for sid, s in self._subs.items()
            ]

    def _notification_loop(
            self,
            sub_id:   str,
            req:      SubscriptionRequest,
            stop_evt: threading.Event):

        period    = req.eventReportingRequirement.repPeriod
        threshold = req.eventReportingRequirement.notifThreshold

        while not stop_evt.wait(period):
            with self._lock:
                if sub_id not in self._subs:
                    break

            try:
                result = self._compute(req)

                if threshold is not None:
                    load = result.get("loadLevelInformation", 0)
                    if load < threshold:
                        continue

                notification = {
                    "subscriptionId": sub_id,
                    "analyticsId":    req.analyticsId,
                    "timeStamp":      datetime.utcnow().isoformat() + "Z",
                    "data":           result
                }
                resp = httpx.post(
                    req.notificationUri,
                    json=notification,
                    timeout=5.0
                )
                print(f"[Sub] Notified {sub_id} → {resp.status_code}")

            except Exception as e:
                print(f"[Sub] Notification error for {sub_id}: {e}")

    def _compute(self, req: SubscriptionRequest) -> dict:
        from anlf.analytics import anlf
        ana_req = AnalyticsRequest(
            analyticsId=req.analyticsId,
            snssaiDnnFilter=req.snssaiDnnFilter or SnssaiDnnFilter(
                snssai=Snssai(), dnn="internet"
            ),
            tgtUe=req.tgtUe
        )
        if req.analyticsId == AnalyticsId.LOAD_LEVEL_INFORMATION:
            return anlf.compute_load_level(ana_req)
        elif req.analyticsId == AnalyticsId.ABNORMAL_BEHAVIOUR:
            return anlf.compute_abnormal_behaviour(ana_req)
        elif req.analyticsId == AnalyticsId.NETWORK_PERFORMANCE:
            return anlf.compute_network_performance(ana_req)
        return {}


subscription_manager = SubscriptionManager()