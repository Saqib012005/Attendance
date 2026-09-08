FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /code

COPY requirements.txt /code/requirements.txt
RUN apt-get update && apt-get install -y tesseract-ocr libglib2.0-0 libsm6 libxext6 libxrender-dev && rm -rf /var/lib/apt/lists/*
RUN pip install --upgrade pip
RUN pip install -r /code/requirements.txt

COPY . /code/

EXPOSE 8000

# Migrate and run (PORT is set by Railway/Render, fallback 8000 for local).
# Seeding is deliberately absent: it creates known-credential accounts and
# re-sets their passwords, which must never happen on an unattended restart.
# Run it by hand when you want demo data: python seed.py --password ...
CMD sh -c "python manage.py migrate && gunicorn --bind 0.0.0.0:${PORT:-8000} attend_backend.wsgi:application"
