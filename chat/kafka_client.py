# myapp/kafka_utils.py
import json
from django.conf import settings
from confluent_kafka import Producer, Consumer

def get_kafka_producer():
    """
    Returns a configured Kafka producer instance.
    """
    # Create a dictionary of configuration settings.
    # This is how you pass settings to the kafka-python client.
    producer_config = {
        'bootstrap.servers': settings.KAFKA_BOOTSTRAP_SERVERS,
        'security.protocol': settings.KAFKA_SECURITY_PROTOCOL,
        'sasl.mechanism': settings.KAFKA_SASL_MECHANISM,
        'sasl.username': settings.KAFKA_SASL_USERNAME,
        'sasl.password': settings.KAFKA_SASL_PASSWORD,
        'ssl.ca.location': settings.KAFKA_CA_LOCATION,
    }
    
    # Instantiate the producer with the configuration
    return Producer(**producer_config)


def get_kafka_consumer(group_id="my-django-consumer-group"):
    """
    Returns a configured Kafka consumer instance.
    """
    consumer_config = {
        'bootstrap.servers': settings.KAFKA_BOOTSTRAP_SERVERS,
        'security.protocol': settings.KAFKA_SECURITY_PROTOCOL,
        'sasl.mechanisms': settings.KAFKA_SASL_MECHANISM,
        'sasl.username': settings.KAFKA_SASL_USERNAME,
        'sasl.password': settings.KAFKA_SASL_PASSWORD,
        'ssl.ca.location': settings.KAFKA_CA_LOCATION,
        'group.id': group_id,
        "enable.auto.commit": False,
        'auto.offset.reset': 'latest',
    }

    return Consumer(consumer_config)
