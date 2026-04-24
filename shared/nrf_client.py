import httpx
import threading
import time
from datetime import datetime
from shared.config import (
    NRF_URL, NWDAF_INSTANCE_ID, NWDAF_SERVICE_IP,
    NWDAF_PORT, PLMN_MCC, PLMN_MNC, HEARTBEAT_INTERVAL
)


class NRFClient:

    def __init__(self):
        self.registered  = False
        self._hb_thread  = None
        self._stop_hb    = threading.Event()

    def register(self) -> bool:
        profile = {
            "nfInstanceId": NWDAF_INSTANCE_ID,
            "nfType":       "NWDAF",
            "nfStatus":     "REGISTERED",
            "plmnList":     [{"mcc": PLMN_MCC, "mnc": PLMN_MNC}],
            "sNssais":      [{"sst": 1, "sd": "010203"}],
            "ipv4Addresses": [NWDAF_SERVICE_IP],
            "nfServices": [
                {
                    "serviceInstanceId": "nnwdaf-analyticsinfo-001",
                    "serviceName":       "nnwdaf-analyticsinfo",
                    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme":          "http",
                    "nfServiceStatus": "REGISTERED",
                    "ipEndPoints": [{
                        "ipv4Address": NWDAF_SERVICE_IP,
                        "transport":   "TCP",
                        "port":        NWDAF_PORT
                    }],
                    "apiPrefix": f"http://{NWDAF_SERVICE_IP}:{NWDAF_PORT}"
                },
                {
                    "serviceInstanceId": "nnwdaf-eventssubscription-001",
                    "serviceName":       "nnwdaf-eventssubscription",
                    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme":          "http",
                    "nfServiceStatus": "REGISTERED",
                    "ipEndPoints": [{
                        "ipv4Address": NWDAF_SERVICE_IP,
                        "transport":   "TCP",
                        "port":        NWDAF_PORT
                    }],
                    "apiPrefix": f"http://{NWDAF_SERVICE_IP}:{NWDAF_PORT}"
                }
            ],
            "customInfo": {
                "analyticsIds": [
                    "LOAD_LEVEL_INFORMATION",
                    "ABNORMAL_BEHAVIOUR",
                    "NETWORK_PERFORMANCE",
                    "UE_COMMUNICATION"
                ]
            }
        }
        try:
            resp = httpx.put(
                f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{NWDAF_INSTANCE_ID}",
                json=profile,
                timeout=10.0
            )
            if resp.status_code in [200, 201]:
                self.registered = True
                print(f"[NRF] Registered ({NWDAF_INSTANCE_ID}) → {resp.status_code}")
                self._start_heartbeat()
                return True
            print(f"[NRF] Registration failed: {resp.status_code}")
            return False
        except Exception as e:
            print(f"[NRF] Registration error: {e}")
            return False

    def _start_heartbeat(self):
        self._stop_hb.clear()
        self._hb_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="nrf-heartbeat"
        )
        self._hb_thread.start()

    def _heartbeat_loop(self):
        while not self._stop_hb.wait(HEARTBEAT_INTERVAL):
            try:
                resp = httpx.patch(
                    f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{NWDAF_INSTANCE_ID}",
                    json=[{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"}],
                    headers={"Content-Type": "application/json-patch+json"},
                    timeout=5.0
                )
                ts = datetime.utcnow().strftime("%H:%M:%S")
                if resp.status_code == 200:
                    print(f"[NRF] Heartbeat OK  {ts}")
                elif resp.status_code == 404:
                    print(f"[NRF] Instance not found in NRF — re-registering  {ts}")
                    self.registered = False
                    self.register()

                else:
                    print(f"[NRF] Heartbeat {resp.status_code} — re-registering  {ts}")
                    self.registered = False
                    self.register()

            except httpx.ConnectError:
                print(f"[NRF] NRF unreachable — will retry in {HEARTBEAT_INTERVAL}s")

            except Exception as e:
                print(f"[NRF] Heartbeat error: {e}")

    def check_nrf_health(self) -> dict:
        try:
            resp = httpx.get(
                f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{NWDAF_INSTANCE_ID}",
                timeout=5.0
            )
            if resp.status_code == 200:
                return {"status": "ok", "registered": True}
            elif resp.status_code == 404:
                return {"status": "ok", "registered": False, "detail": "not registered"}
            return {"status": "error", "code": resp.status_code}
        except httpx.ConnectError:
            return {"status": "error", "detail": "NRF unreachable"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def deregister(self):
        self._stop_hb.set()
        try:
            httpx.delete(
                f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{NWDAF_INSTANCE_ID}",
                timeout=5.0
            )
            self.registered = False
            print(f"[NRF] Deregistered {NWDAF_INSTANCE_ID}")
        except Exception as e:
            print(f"[NRF] Deregister error: {e}")

    def discover(self, target_nf_type: str, service_name: str = None) -> list:
        params = {
            "target-nf-type":    target_nf_type,
            "requester-nf-type": "NWDAF"
        }
        if service_name:
            params["service-names"] = service_name
        try:
            resp = httpx.get(
                f"{NRF_URL}/nnrf-disc/v1/nf-instances",
                params=params,
                timeout=5.0
            )
            if resp.status_code == 200:
                return resp.json().get("nfInstances", [])
        except Exception as e:
            print(f"[NRF] Discovery error: {e}")
        return []


nrf_client = NRFClient()