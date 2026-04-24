from elasticsearch import Elasticsearch
from shared.config import (
    ES_HOST, ES_USER, ES_PASSWORD, ES_INDEX,
)


class ADRFClient:

    def __init__(self):
        self._es = Elasticsearch(
            ES_HOST,
            basic_auth=(ES_USER, ES_PASSWORD),
            verify_certs=False
        )

    def get_n3_load(self, window_minutes: int = 5) -> dict:
        resp = self._es.search(
            index=ES_INDEX,
            body={
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
                            {"term":  {"labels.interface_5g.keyword": "N3-GTP-U"}},
                            {"term":  {"type.keyword": "flow"}}
                        ]
                    }
                },
                "aggs": {
                    "total_bytes":   {"sum":         {"field": "network.bytes"}},
                    "total_packets": {"sum":         {"field": "network.packets"}},
                    "total_flows":   {"value_count": {"field": "flow.id.keyword"}},
                    "uplink_bytes": {
                        "filter": {"term": {"source.port": 2152}},
                        "aggs":   {"bytes": {"sum": {"field": "network.bytes"}}}
                    },
                    "downlink_bytes": {
                        "filter": {"term": {"source.port": 2152}},
                        "aggs":   {"bytes": {"sum": {"field": "network.bytes"}}}
                    },
                    "avg_flow_duration_ns": {"avg": {"field": "event.duration"}},
                    "bytes_per_minute": {
                        "date_histogram": {
                            "field":          "@timestamp",
                            "fixed_interval": "1m"
                        },
                        "aggs": {
                            "bytes":   {"sum":         {"field": "network.bytes"}},
                            "packets": {"sum":         {"field": "network.packets"}},
                            "flows":   {"value_count": {"field": "flow.id.keyword"}}
                        }
                    }
                }
            }
        )
        aggs = resp["aggregations"]
        return {
            "total_bytes":          aggs["total_bytes"]["value"]              or 0,
            "total_packets":        aggs["total_packets"]["value"]            or 0,
            "total_flows":          aggs["total_flows"]["value"]              or 0,
            "uplink_bytes":         aggs["uplink_bytes"]["bytes"]["value"]    or 0,
            "downlink_bytes":       aggs["downlink_bytes"]["bytes"]["value"]  or 0,
            "avg_flow_duration_ns": aggs["avg_flow_duration_ns"]["value"]     or 0,
            "bytes_per_minute":     aggs["bytes_per_minute"]["buckets"],
            "window_minutes":       window_minutes
        }

    def get_n3_anomaly(self, window_minutes: int = 10) -> dict:
        resp = self._es.search(
            index=ES_INDEX,
            body={
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
                            {"terms": {"labels.interface_5g.keyword": ["N3-GTP-U", "N2-NGAP"]}}
                        ]
                    }
                },
                "aggs": {
                    "per_interface": {
                        "terms": {"field": "labels.interface_5g.keyword"},
                        "aggs": {
                            "last_5m": {
                                "filter": {"range": {"@timestamp": {"gte": "now-5m"}}},
                                "aggs": {
                                    "bytes": {"sum":         {"field": "network.bytes"}},
                                    "flows": {"value_count": {"field": "flow.id.keyword"}}
                                }
                            },
                            "prev_5m": {
                                "filter": {"range": {
                                    "@timestamp": {"gte": "now-10m", "lt": "now-5m"}
                                }},
                                "aggs": {
                                    "bytes": {"sum":         {"field": "network.bytes"}},
                                    "flows": {"value_count": {"field": "flow.id.keyword"}}
                                }
                            }
                        }
                    }
                }
            }
        )
        result = {}
        for bucket in resp["aggregations"]["per_interface"]["buckets"]:
            iface = bucket["key"]
            result[iface] = {
                "last_5m_bytes": bucket["last_5m"]["bytes"]["value"] or 0,
                "prev_5m_bytes": bucket["prev_5m"]["bytes"]["value"] or 0,
                "last_5m_flows": bucket["last_5m"]["flows"]["value"] or 0,
                "prev_5m_flows": bucket["prev_5m"]["flows"]["value"] or 0,
            }
        return result
    
    def get_general_anomaly(self, window_minutes: int = 15, lag_minutes: int = 5) -> dict:
        window_step = window_minutes//3
        t_start_oldest = window_minutes + lag_minutes
        t_start_middle = (window_minutes - window_step) + lag_minutes
        t_start_latest = window_step + lag_minutes
        resp = self._es.search(
            index=ES_INDEX,
            body={
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
                        {"term":  {"flow.final": True}}
                    ]
                }
            },
            "aggs": {
                "traffic_over_time": {
                    "filters": {
                        "filters": {
                            "oldest": {"range": {"@timestamp": {
                                "gte": f"now-{t_start_oldest}m",
                                "lt":  f"now-{t_start_middle}m"
                            }}},
                            "middle": {"range": {"@timestamp": {
                                "gte": f"now-{t_start_middle}m",
                                "lt":  f"now-{t_start_latest}m"
                            }}},
                            "latest": {"range": {"@timestamp": {
                                "gte": f"now-{t_start_latest}m"
                            }}},
                        }
                    },
                    "aggs": {
                        "avg_bytes":     {"avg":         {"field": "network.bytes"}},
                        "total_bytes":   {"sum":         {"field": "network.bytes"}},
                        "total_packets": {"sum":         {"field": "network.packets"}},
                        "unique_flows":  {"cardinality": {"field": "flow.id.keyword"}},
                        "avg_duration":  {"avg":         {"field": "event.duration"}},
                        "src_bytes":     {"sum":         {"field": "source.bytes"}},
                        "dst_bytes":     {"sum":         {"field": "destination.bytes"}},
                    }
                }
            }
        }
        )
        buckets = resp["aggregations"]["traffic_over_time"]["buckets"]
        return {
            "window_minutes": window_minutes,
            "step_minutes":   window_step,
            "oldest":         self._anomaly_extract(buckets["oldest"]),
            "middle":         self._anomaly_extract(buckets["middle"]),
            "latest":         self._anomaly_extract(buckets["latest"]),
        }
    
    def _anomaly_extract(self, sub_bucket: dict) -> dict:
        return {
            "doc_count":     sub_bucket["doc_count"],
            "avg_bytes":     sub_bucket["avg_bytes"]["value"]     or 0,
            "total_bytes":   sub_bucket["total_bytes"]["value"]   or 0,
            "total_packets": sub_bucket["total_packets"]["value"] or 0,
            "unique_flows":  sub_bucket["unique_flows"]["value"]  or 0,
            "avg_duration":  sub_bucket["avg_duration"]["value"]  or 0,
            "src_bytes":     sub_bucket["src_bytes"]["value"]     or 0,
            "dst_bytes":     sub_bucket["dst_bytes"]["value"]     or 0,
        }
    
    def get_network_performance(self, window_minutes: int = 5) -> dict:
        resp = self._es.search(
            index=ES_INDEX,
            body={
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
                            {"term":  {"labels.interface_5g.keyword": "N3-GTP-U"}}
                        ]
                    }
                },
                "aggs": {
                    "total_bytes":     {"sum": {"field": "network.bytes"}},
                    "total_packets":   {"sum": {"field": "network.packets"}},
                    "avg_duration_ns": {"avg": {"field": "event.duration"}},
                    "max_bytes_flow":  {"max": {"field": "network.bytes"}},
                }
            }
        )
        aggs = resp["aggregations"]
        return {
            "total_bytes":     aggs["total_bytes"]["value"]     or 0,
            "total_packets":   aggs["total_packets"]["value"]   or 0,
            "avg_duration_ns": aggs["avg_duration_ns"]["value"] or 0,
            "max_bytes_flow":  aggs["max_bytes_flow"]["value"]  or 0,
            "window_minutes":  window_minutes
        }

    def health_check(self) -> dict:
        try:
            resp = self._es.count(
                index=ES_INDEX,
                body={"query": {"term": {"labels.interface_5g.keyword": "N3-GTP-U"}}}
            )
            return {"status": "ok", "n3_doc_count": resp["count"]}
        except Exception as e:
            return {"status": "error", "detail": str(e)}


adrf = ADRFClient()