import base64
import hashlib
import hmac
import json
import time

from django.conf import settings

QR_PERIOD_SECONDS = 20
QR_TRANSITION_SECONDS = 10
MIN_SENSOR_SAMPLES = 10
MIN_SENSOR_DURATION_MS = 3000
MAX_SENSOR_DURATION_MS = 15000


def _secret():
    return getattr(settings, 'ATTENDANCE_SIGNING_SECRET', settings.SECRET_KEY).encode()


def _sign(data):
    canonical = json.dumps(data, separators=(',', ':'), sort_keys=True).encode()
    return hmac.new(_secret(), canonical, hashlib.sha256).hexdigest()


def get_epoch_captcha(session_id, epoch):
    h = hmac.new(_secret(), f'captcha:{session_id}:{epoch}'.encode(), hashlib.sha256).hexdigest()
    return f'{int(h[:6], 16) % 10000:04d}'


def issue_epoch(session, now=None):
    now = int(now or time.time())
    epoch = now // QR_PERIOD_SECONDS
    captcha = get_epoch_captcha(session.session_id, epoch)
    payload = {
        'sessionId': str(session.session_id),
        'epoch': epoch,
        'issuedAt': epoch * QR_PERIOD_SECONDS,
        'expiresAt': (epoch + 1) * QR_PERIOD_SECONDS + QR_TRANSITION_SECONDS,
    }
    payload['signature'] = _sign(payload)
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
    return {
        'qr_payload': encoded,
        'captcha': captcha,
        'epoch': epoch,
        'expires_at': payload['expiresAt'],
        'server_time': now,
    }


def validate_qr(encoded, session, now=None):
    now = int(now or time.time())
    try:
        raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
        payload = json.loads(raw)
        signature = payload.pop('signature')
    except Exception:
        return False, False, None
    authentic = hmac.compare_digest(signature, _sign(payload))
    authentic = authentic and payload.get('sessionId') == str(session.session_id)
    epoch = payload.get('epoch')
    current_epoch = now // QR_PERIOD_SECONDS
    fresh = authentic and (epoch is not None) and (epoch in (current_epoch, current_epoch - 1, current_epoch - 2))
    return authentic, fresh, epoch


def validate_captcha(session, epoch, student_id, answer):
    if epoch is None or not answer:
        return False
    ans_str = str(answer).strip()
    expected_current = get_epoch_captcha(session.session_id, epoch)
    expected_prev = get_epoch_captcha(session.session_id, epoch - 1)
    return hmac.compare_digest(expected_current, ans_str) or hmac.compare_digest(expected_prev, ans_str)


def validate_sensor_summary(summary, sensor):
    """Validate compact client-observed features without retaining raw readings."""
    if not isinstance(summary, dict):
        return 'invalid'
    if summary.get('available') is False:
        return 'unavailable'
    if summary.get('timedOut') is True:
        return 'timeout'
    try:
        samples = int(summary['sampleCount'])
        duration = int(summary['durationMs'])
        interaction = float(summary['interaction'])
    except (KeyError, TypeError, ValueError):
        return 'invalid'
    if samples < MIN_SENSOR_SAMPLES or duration < MIN_SENSOR_DURATION_MS:
        return 'fail'
    threshold = 0.01 if sensor == 'gyroscope' else 0.05
    return 'pass' if interaction >= threshold else 'fail'