from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny


@method_decorator(ensure_csrf_cookie, name='dispatch')
class GetCSRFToken(APIView):
    authentication_classes = []  # Disable authentication
    permission_classes = [AllowAny]

    def get(self, request, format=None):
        return Response({'csrfToken': get_token(request)})
