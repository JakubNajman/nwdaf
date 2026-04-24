import signal
import sys
from flask import Flask, request, jsonify, Response
from pydantic import ValidationError
from shared.models import AnalyticsRequest, AnalyticsId, SubscriptionRequest
from shared.nrf_client import nrf_client
from adrf.client import adrf
from anlf.analytics import anlf
from api.subscriptions import subscription_manager

app = Flask(__name__)


def startup():
    print("[NWDAF] Starting up...")

    health = adrf.health_check()
    print(f"[NWDAF] ADRF health: {health}")

    nrf_health = nrf_client.check_nrf_health()
    print(f"[NWDAF] NRF:  {nrf_health}")

    if nrf_health["status"] == "ok":
        registered = nrf_client.register()
        if not registered:
            print("[NWDAF] NRF registration failed — continuing without NRF")
    else:
        print(f"[NWDAF] NRF unreachable — skipping registration, will retry via heartbeat")

    print("[NWDAF] Ready.")


def shutdown(sig=None, frame=None):
    print("[NWDAF] Shutting down...")
    nrf_client.deregister()
    sys.exit(0)


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT,  shutdown)


@app.route("/nnwdaf-analyticsinfo/v1/analytics", methods=["POST"])
def get_analytics():
    try:
        req = AnalyticsRequest(**request.get_json(force=True))
    except (ValidationError, TypeError) as e:
        return jsonify({"status": 400, "detail": str(e)}), 400

    try:
        if req.analyticsId == AnalyticsId.ABNORMAL_BEHAVIOUR:
            result = anlf.compute_abnormal_behaviour_general(req)

        else:
            return jsonify({
                "status": 400,
                "detail": f"Analytics ID '{req.analyticsId}' not yet implemented"
            }), 400

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"status": 500, "detail": str(e)}), 500


@app.route("/nnwdaf-eventssubscription/v1/subscriptions", methods=["POST"])
def subscribe():
    try:
        req = SubscriptionRequest(**request.get_json(force=True))
    except (ValidationError, TypeError) as e:
        return jsonify({"status": 400, "detail": str(e)}), 400

    result = subscription_manager.subscribe(req)
    return jsonify(result), 201


@app.route(
    "/nnwdaf-eventssubscription/v1/subscriptions/<subscription_id>",
    methods=["PUT"]
)
def update_subscription(subscription_id: str):
    try:
        req = SubscriptionRequest(**request.get_json(force=True))
    except (ValidationError, TypeError) as e:
        return jsonify({"status": 400, "detail": str(e)}), 400

    try:
        result = subscription_manager.update(subscription_id, req)
        return jsonify(result), 200
    except KeyError:
        return jsonify({"status": 404, "detail": f"{subscription_id} not found"}), 404


@app.route(
    "/nnwdaf-eventssubscription/v1/subscriptions/<subscription_id>",
    methods=["DELETE"]
)
def unsubscribe(subscription_id: str):
    try:
        subscription_manager.unsubscribe(subscription_id)
        return Response(status=204)
    except KeyError:
        return jsonify({"status": 404, "detail": f"{subscription_id} not found"}), 404


@app.route("/nnwdaf-eventssubscription/v1/subscriptions", methods=["GET"])
def list_subscriptions():
    return jsonify({"subscriptions": subscription_manager.list_subscriptions()}), 200


@app.route("/nnwdaf-analyticsinfo/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status":        "ok",
        "nrf":           nrf_client.check_nrf_health(),
        "adrf":          adrf.health_check(),
        "subscriptions": len(subscription_manager._subs)
    }), 200


if __name__ == "__main__":
    startup()
    app.run(host="0.0.0.0", port=8080, debug=False)