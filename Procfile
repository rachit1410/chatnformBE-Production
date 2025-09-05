web: uvicorn core.asgi:application --host 0.0.0.0 --port $PORT
worker: python task_manager.py kafka
cron: python task_manager.py cleanup
celery: celery -A core worker --loglevel=info