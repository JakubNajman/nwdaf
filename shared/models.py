from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum
from uuid import uuid4


class AnalyticsId(str, Enum):
    LOAD_LEVEL_INFORMATION  = "LOAD_LEVEL_INFORMATION"
    NETWORK_PERFORMANCE     = "NETWORK_PERFORMANCE"
    ABNORMAL_BEHAVIOUR      = "ABNORMAL_BEHAVIOUR"
    SERVICE_EXPERIENCE      = "SERVICE_EXPERIENCE"
    UE_MOBILITY             = "UE_MOBILITY"
    UE_COMMUNICATION        = "UE_COMMUNICATION"
    EXPECTED_UE_BEHAVIOUR   = "EXPECTED_UE_BEHAVIOURAL_PARAMETERS"
    DN_PERFORMANCE          = "DN_PERFORMANCE"
    DISPERSION              = "DISPERSION"


class ReqAnaType(str, Enum):
    HIST          = "HIST"           # historical statistics
    PRED          = "PRED"           # predictions
    HIST_AND_PRED = "HIST_AND_PRED"  # both


class Snssai(BaseModel):
    sst: int = 1
    sd:  str = "010203"


class PlmnId(BaseModel):
    mcc: str = "208"
    mnc: str = "93"


class SnssaiDnnFilter(BaseModel):
    snssai: Snssai
    dnn:    str = "internet"


class TgtUe(BaseModel):
    anyUe:         Optional[bool] = None
    supi:          Optional[str]  = None
    exterGroupId:  Optional[str]  = None


class AnalyticsRequest(BaseModel):
    analyticsId:       AnalyticsId
    reqAnaType:        ReqAnaType              = ReqAnaType.HIST
    reqPeriod:         Optional[str]           = "PT5M"   # ISO 8601 duration
    tgtUe:             Optional[TgtUe]         = None
    snssaiDnnFilter:   Optional[SnssaiDnnFilter] = None
    startTs:           Optional[datetime]      = None
    endTs:             Optional[datetime]      = None


class LoadLevelResponse(BaseModel):
    analyticsId:            str = "LOAD_LEVEL_INFORMATION"
    snssai:                 Snssai
    dnn:                    str
    loadLevelInformation:   float               # 0–100 %
    confidence:             int = 95            # 0–100 %
    timeStamp:              str
    extraData:              Optional[dict] = None


class AbnormalBehaviourResponse(BaseModel):
    analyticsId:        str = "ABNORMAL_BEHAVIOUR"
    snssai:             Snssai
    abnormalBehaviour:  bool
    cause:              Optional[str] = None
    confidence:         int = 85
    timeStamp:          str
    extraData:          Optional[dict] = None


class NetworkPerformanceResponse(BaseModel):
    analyticsId:            str = "NETWORK_PERFORMANCE"
    snssai:                 Snssai
    dnn:                    str
    confidence:             int = 90
    timeStamp:              str
    networkPerformanceInfo: dict


class NotifMethod(str, Enum):
    PERIODIC   = "PERIODIC"
    THRESHOLD  = "THRESHOLD"
    ONE_TIME   = "ONE_TIME"


class EventReportingRequirement(BaseModel):
    notifMethod:    NotifMethod = NotifMethod.PERIODIC
    repPeriod:      int         = 30        # seconds
    notifThreshold: Optional[float] = None  # load % to trigger on


class SubscriptionRequest(BaseModel):
    analyticsId:                 AnalyticsId
    notificationUri:             str
    eventReportingRequirement:   EventReportingRequirement
    snssaiDnnFilter:             Optional[SnssaiDnnFilter] = None
    tgtUe:                       Optional[TgtUe]           = None
    expiry:                      Optional[str]             = None


class SubscriptionResponse(BaseModel):
    subscriptionId: str = Field(default_factory=lambda: f"sub-{uuid4().hex[:8]}")
    analyticsId:    str
    expiry:         Optional[str] = None


class EventNotification(BaseModel):
    subscriptionId: str
    analyticsId:    str
    timeStamp:      str
    data:           dict