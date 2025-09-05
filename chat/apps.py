from django.apps import AppConfig
from .kafka_utils import producer

class ChatConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'chat'
    
    def ready(self):
        import atexit
        atexit.register(lambda: producer.flush(5))