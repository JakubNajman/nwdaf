import os
from dotenv import load_dotenv

load_dotenv()

ES_HOST     = os.getenv("ES_HOST",     "https://192.168.61.100:30920")
ES_USER     = os.getenv("ES_USER",     "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "oUNsRiuMeHC3wUGpoBIh6TCL")
ES_INDEX    = os.getenv("ES_INDEX",    "packetbeat-free5gc-*")

NRF_URL = os.getenv("NRF_URL", "http://nrf-nnrf.free5gc.svc.cluster.local:8000")

KSERVE_URL = os.getenv("KSERVE_URL", "http://192.168.60.4:31091")
KSERVE_HOST = os.getenv("KSERVE_HOST", "nwdaf-traffic-anomaly.kubeflow-user-example-com.svc.cluster.local")
MODEL_NAME = os.getenv("MODEL_NAME", "nwdaf-traffic-anomaly")
MODEL_NS   = os.getenv("MODEL_NS",   "kubeflow-user-example-com")

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://192.168.60.100:30901/")
MINIO_ACCESS   = os.getenv("MINIO_ACCESS",   "minioadmin")
MINIO_SECRET   = os.getenv("MINIO_SECRET",   "minioadmin123")
MINIO_BUCKET   = os.getenv("MINIO_BUCKET",   "")

NWDAF_INSTANCE_ID = os.getenv("NWDAF_INSTANCE_ID", "nwdaf-001")
NWDAF_SERVICE_IP  = os.getenv("NWDAF_SERVICE_IP",  "nwdaf-service.free5gc.svc.cluster.local")
NWDAF_PORT        = int(os.getenv("NWDAF_PORT",    "8080"))
PLMN_MCC          = os.getenv("PLMN_MCC", "208")
PLMN_MNC          = os.getenv("PLMN_MNC", "93")

LINK_CAPACITY_BPS   = int(float(os.getenv("LINK_CAPACITY_BPS",   "100000000")))  # 100 Mbps
ANOMALY_SPIKE_RATIO = float(os.getenv("ANOMALY_SPIKE_RATIO",     "3.0"))
HEARTBEAT_INTERVAL  = int(os.getenv("HEARTBEAT_INTERVAL",        "30"))
DEFAULT_WINDOW_MIN  = int(os.getenv("DEFAULT_WINDOW_MIN",        "5"))