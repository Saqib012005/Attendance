web: python backend/manage.py migrate && python backend/seed.py --password password123 && gunicorn --chdir backend --bind 0.0.0.0:$PORT attend_backend.wsgi:application


