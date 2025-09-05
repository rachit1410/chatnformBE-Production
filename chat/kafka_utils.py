# kafka_utils.py
import json
import logging
from .kafka_client import get_kafka_producer

logger = logging.getLogger(__name__)

producer = get_kafka_producer()


def delivery_report(err, msg):
    if err:
        logger.error(f"Message delivery failed: {err}")
    else:
        logger.info(f"Delivered to {msg.topic()} [{msg.partition()}] offset {msg.offset()}")


def send_realtime_event(topic, message_data, origin=None):
    if origin:
        message_data["origin"] = origin
    try:
        producer.produce(
            topic,
            value=json.dumps(message_data).encode("utf-8"),
            callback=delivery_report
        )
        # allow background thread to handle delivery callbacks
        producer.poll(0)
    except BufferError as e:
        logger.error(f"Local producer queue is full: {e}")
