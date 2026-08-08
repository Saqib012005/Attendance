#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

# Remove GSoC Django from sys.path to prevent conflicts with this project
sys.path = [p for p in sys.path if 'gsoc\\django' not in p.lower() and 'gsoc/django' not in p.lower()]

def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'attend_backend.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()