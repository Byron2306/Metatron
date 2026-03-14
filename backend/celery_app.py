import os
from celery import Celery

# Celery configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', REDIS_URL)
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', REDIS_URL)


celery_app = Celery('metatron_seraph_tasks', broker=CELERY_BROKER_URL, backend=CELERY_RESULT_BACKEND)

# Optional: load additional config from env
celery_app.conf.update(
    task_track_started=True,
    accept_content=['json'],
    task_serializer='json',
    result_serializer='json',
    task_soft_time_limit=int(os.environ.get('CELERY_TASK_SOFT_TIME_LIMIT', 3600)),
    task_time_limit=int(os.environ.get('CELERY_TASK_TIME_LIMIT', 4000)),
    worker_send_task_events=True,
    worker_redirect_stdouts_level='INFO'
)

# Import tasks so Celery discovers them when worker starts
try:
    # tasks package
    import backend.tasks.integrations_tasks  # noqa: F401
    import backend.tasks.triune_tasks  # noqa: F401
    import backend.tasks.world_ingest_tasks  # noqa: F401
except Exception:
    # Best-effort import; tasks module may not be present during some operations
    pass
