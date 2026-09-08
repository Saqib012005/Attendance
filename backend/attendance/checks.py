"""Deploy-time system checks for the presence layer's configuration.

`manage.py check` already runs in CI and again as the first thing `runserver` and
`migrate` do, so this is the cheapest place to catch a configuration that would
otherwise fail one request at a time in production.

Both checks are errors rather than warnings, because both describe a deployment that
cannot do its job:

* An artifact that will not load means `PRESENCE_CONFIG_VERSION` names a version this
  build does not ship, or the JSON on disk is invalid. Every proof submitted against
  a session opened under it answers 503, and no session opened afterwards can even be
  created - `PresenceSession.open` reads `active()` to pin a version.
* A failed cross-check means the parameters are individually in range and mutually
  contradictory. The specific failures it catches are silent in production rather
  than loud: a nonce retention shorter than the offline allowance accepts replays, an
  inverted review band makes the review outcome unreachable, and an operating point
  above the sum of the weights refuses every proof no matter how much evidence it
  carries. None of those raises anything at runtime; each just quietly decides wrong.

Deliberately *not* checked here: that the active artifact is calibrated. Shipping
uncalibrated is the honest current state of this build, and a check that failed on it
would either block every deploy or be permanently silenced, which is how a real
signal becomes noise. `calibration` is reported on every decision instead.
"""
from django.core.checks import Error, register, Tags


@register(Tags.compatibility)
def presence_config_loads(app_configs, **kwargs):
    """The active configuration artifact exists, parses and validates."""
    from .presence import config
    try:
        artifact = config.active()
    except config.ConfigError as exc:
        return [Error(
            'The active presence configuration cannot be loaded: %s' % exc,
            hint='%s selects the artifact; available versions are %s. Artifacts live '
                 'in attendance/presence/config/ as presence-<version>.json.'
                 % (config.ENV_VERSION, ', '.join(config.available_versions()) or 'none'),
            id='attendance.E001',
        )]
    if not artifact.version:
        return [Error(
            'The active presence configuration has no version string.',
            hint='Every artifact must name itself; a decision that cannot name the '
                 'parameters that produced it cannot be re-derived.',
            id='attendance.E002',
        )]
    return []


@register(Tags.compatibility)
def presence_config_is_consistent(app_configs, **kwargs):
    """The relationships between parameters that no single bound can express."""
    from .presence import config
    try:
        problems = config.cross_check()
    except config.ConfigError:
        # Already reported by the check above, with the detail. Reporting it twice
        # would make one misconfiguration look like two.
        return []
    return [
        Error(
            'Presence configuration is internally inconsistent: %s' % problem,
            hint='Artifacts are added, never edited. Ship a new version with the '
                 'relationship satisfied rather than amending the active one.',
            id='attendance.E003',
        )
        for problem in problems
    ]
