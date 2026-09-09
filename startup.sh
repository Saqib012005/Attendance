#!/bin/bash
cd backend
echo "Running database migrations..."
python manage.py migrate
# Seeding is opt-in. It creates known-credential accounts (including a
# superuser) and it re-sets their passwords on every run, so it must never fire
# on an unattended production restart. seed.py refuses on its own too; this is
# the outer of the two gates.
if [ "$SEED_ON_START" = "1" ]; then
  echo "Seeding database (SEED_ON_START=1)..."
  python seed.py
else
  echo "Skipping seed (set SEED_ON_START=1 to enable)."
fi
echo "Starting Gunicorn server..."
gunicorn attend_backend.wsgi:application --bind=0.0.0.0:8000 --timeout 600
