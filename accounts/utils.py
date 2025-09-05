import random
from django.core.cache import cache
from accounts.models import VerifiedEmail
import re


def generate_otp(email):
    blocked = f"blocked:{email}"
    otp_cache = f"otp:{email}"
    otp = str(random.randint(100000, 999999))
    expiry_blocklist = 60*60*12
    expiry_otp = 60*12

    tries = cache.get(blocked) or 0
    tries += 1
    cache.set(blocked, tries, expiry_blocklist)
    cache.set(otp_cache, otp, expiry_otp)
    return otp


def varify_otp(email, otp):
    otp_cached = cache.get(f"otp:{email}")
    return otp_cached == str(otp)


def is_verified(email):
    VEmail, _ = VerifiedEmail.objects.get_or_create(email=email)
    return VEmail.verified


def validate_new_passsword(password):
    password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$'
    return re.match(password_regex, password)
