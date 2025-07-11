# gunicorn_config.py
bind = "0.0.0.0:5001"
workers = 4  # Använd alla CPU-kärnor
worker_class = "sync"
worker_connections = 1000
timeout = 300  # 5 minuter för stora PDF:er
keepalive = 5
max_requests = 1000
max_requests_jitter = 50