# your_app/authentication.py
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model

class HttpOnlyJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        User = get_user_model()
        access_token = request.COOKIES.get('access_token')

        if not access_token:
            return None # Authentication failed, but allows anonymous access for some views

        try:
            # Validate the access token
            # It will raise an exception if the token is invalid or expired
            payload = AccessToken(access_token).payload
            
            # You might need to get the user from the database
            # based on the user ID in the token's payload
            user_id = payload.get('user_id')
            user = User.objects.get(id=user_id)
            
            return (user, access_token)

        except Exception:
            raise AuthenticationFailed('Token is invalid or expired')