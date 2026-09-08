from django.apps import AppConfig


class AttendanceConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'attendance'

    def ready(self):
        # Registers the presence configuration checks. Imported here rather than at
        # module scope because the checks reach into `presence.config`, which reads
        # settings, and an AppConfig module is imported before the app registry is
        # ready. `manage.py check` runs these, and so does every `runserver` and
        # `migrate`, which is what makes a bad PRESENCE_CONFIG_VERSION a failed
        # deploy rather than a run of 503s.
        from . import checks  # noqa: F401
