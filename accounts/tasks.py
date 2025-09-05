from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings


@shared_task
def send_otp(subject, message, email):
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )
