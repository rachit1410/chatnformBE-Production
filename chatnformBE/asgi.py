"""
ASGI config for chatnformBE project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'chatnformBE.settings')
django_asgi_app = get_asgi_application()

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from channels.auth import AuthMiddlewareStack
import chat.routing
from chatnformBE.middleware.ws_middleware import TokenAuthMiddleware as T


application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket":  AllowedHostsOriginValidator(
            T(
                AuthMiddlewareStack(
                    URLRouter(
                        chat.routing.websocket_urlpatterns
                    )
                )
            )
        )
    }
)
