import logging
import token
from rest_framework.views import APIView
from accounts.serializers import UserRegisterSerializer, UserLoginSerializer, CNFUserSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model, authenticate
from rest_framework.response import Response
from accounts.utils import generate_otp, is_verified, varify_otp, validate_new_passsword
from django.core.cache import cache
from accounts.models import VerifiedEmail
from rest_framework_simplejwt.tokens import RefreshToken
from accounts.tasks import send_otp
from rest_framework.parsers import MultiPartParser, FormParser
import uuid
logger = logging.getLogger(__name__)
User = get_user_model()


# new registeration
class RegisterApiView(APIView):
    authentication_classes = []  # No authentication needed for this view
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data
            email = data.get("email")
            if not is_verified(email):
                return Response(
                    {
                        "status": False,
                        "message": "email not verified.",
                        "data": {}
                    }
                )

            serializer = UserRegisterSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": True,
                        "message": "acount created.",
                        "data": serializer.data.get("email")
                    }
                )
            logger.warning(f"Registration failed: {serializer.errors}")
            return Response(
                {
                    "status": False,
                    "message": serializer.errors,
                    "data": {}
                }
            )
        except Exception as e:
            logger.error(f"Exception in RegisterApiView: {e}", exc_info=True)
            return Response(
                {
                    "status": False,
                    "message": "something went wrong",
                    "data": {}
                }
            )


class SendOTP(APIView):
    authentication_classes = [] # No authentication needed for this view
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = request.data.get('email')
            logger.info(f"Received email verification request for: {email}")

            if is_verified(email):
                logger.info(f"Email already verified: {email}")
                return Response(
                    {
                        "status": True,
                        "message": "email already verified.",
                        "data": {
                            "verified": True
                        }
                    }
                )

            if tries := cache.get(f"blocked:{email}"):
                if tries > 5:
                    logger.warning(f"OTP request throttled for: {email}")
                    return Response(
                        {
                            "status": False,
                            "message": "You have used all your retries, Please come back after a day.",
                            "data": {}
                        }
                    )

            generate_otp(email)
            otp = cache.get(f"otp:{email}")
            
            plain_message = (
                f"Hi there,\n\n"
                f"You recently requested a One-Time Password (OTP) to verify your email address.\n\n"
                f"Your OTP is: {otp}\n\n"
                f"This code is valid for the next 10 minutes. Please do not share this with anyone. "
                f"If you did not request this OTP, please ignore this email.\n\n"
                f"Thank you,\n"
                f"The ChatNForm"
            )
            if hasattr(send_otp, "deley"):
                send_otp.deley(
                    subject="OTP for email verification.",
                    message=plain_message,
                    email=email
                )
            else:
                send_otp(
                    subject="OTP for email verification.",
                    message=plain_message,
                    email=email
                )
            logger.info(f"Sent OTP email to: {email}")

            return Response(
                {
                    "status": True,
                    "message": "otp sent.",
                    "data": {
                        "verified": False
                    }
                }
            )
        except Exception as e:
            logger.error(f"Exception in VerifyEmail GET: {e}", exc_info=True)
            return Response(
                {
                    "status": False,
                    "message": "something went wrong",
                    "data": {}
                },
            )


class VerifyEmail(APIView):
    authentication_classes = []  # No authentication needed for this view
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data
            if not data:
                data = request.POST
            otp = data.get("otp")
            email = data.get("email")
            logger.info(f"Received OTP verification for: {email}")
            if varify_otp(email=email, otp=otp):
                verify_email = VerifiedEmail.objects.get(email=email)
                verify_email.verified = True
                verify_email.save()
                logger.info(f"Email verified successfully: {email}")
            else:
                logger.warning(f"Invalid OTP for {email}")
                return Response(
                    {
                        "status": False,
                        "message": "incorrect or expired OTP.",
                        "data": {},
                    }
                )
            return Response(
                {
                    "status": True,
                    "message": "email verified",
                    "data": {}
                }
            )
        except Exception as e:
            logger.error(f"Exception in verifyEmail GET: {e}", exc_info=True)
            return Response(
                {
                    "status": False,
                    "message": "something went wrong",
                    "data": {}
                }
            )


class TokenRefreshView(APIView):
    authentication_classes = []  # No authentication needed for this view
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response(
                {'status': False, 'message': 'No refresh token'}, status=401
            )
        try:
            refresh = RefreshToken(refresh_token)
            # This generates a new access token and sets it in the cookie
            res = Response(
                {
                    'status': True,
                    'message': 'Token refreshed.',
                    'data': {
                        'accessExpiry': refresh.access_token.payload.get('exp'),
                    }
                }
            )
            res.set_cookie(
                key='access_token',
                value=str(refresh.access_token),
                httponly=True,
                secure=True,
                samesite='Strict',
                max_age=40 * 60, # 40 minutes in seconds
            )
            return res
        except Exception:
            return Response({'status': False, 'message': 'Invalid refresh token'}, status=401)


# login
class LoginApiView(APIView):
    authentication_classes = []  # No authentication needed for this view
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data
            serializer = UserLoginSerializer(data=data)
            if serializer.is_valid():
                email = serializer.validated_data.get("email")
                password = serializer.validated_data.get("password")
                if not is_verified(email=email):
                    logger.error(f"Account exist without email verification: {email}.")
                    return Response(
                        {
                            "status": False,
                            "message": "Your email is not verified. Please verify your email.",
                            "data": {}
                        }, status=400
                    )

                authenticated_user = authenticate(request=request, email=email, password=password)

                if authenticated_user is None:
                    logger.warning(f"Attempted login with wrong password on account: {email}")
                    return Response(
                        {
                            "status": False,
                            "message": "incorrect password",
                            "data": {}
                        }, status=400
                    )

                token = RefreshToken.for_user(authenticated_user)
                res = Response(
                    {
                        "status": True,
                        "message": "Logged in successfully",
                        "data": {
                            "accessExpiry": token.access_token.payload.get("exp"),
                        }
                    }
                )

                res.set_cookie(
                    key='refresh_token',
                    value=str(token),
                    httponly=True,
                    secure=True,
                    samesite='Strict',
                    max_age=7 * 24 * 3600, # 7 days
                )
                
                res.set_cookie(
                    key='access_token',
                    value=str(token.access_token),
                    httponly=True,
                    secure=True,
                    samesite='Lax',
                    max_age= 40 * 3600, # 40 minutes
                )

                return res
            logger.warning(f"Registration failed: {serializer.errors}")
            return Response(
                {
                    "status": False,
                    "message": serializer.errors,
                    "data": {}
                }, status=400
            )

        except Exception as e:
            logger.error(f"Exception in verifyEmail GET: {e}", exc_info=True)
            return Response(
                {
                    "status": False,
                    "message": "something went wrong",
                    "data": {}
                }, status=400
            )

    def delete(self, request):
        res = Response({'status': True, 'message': 'Logged out successfully.'})
        # Blacklist the refresh token
        refresh_token = request.COOKIES.get('refresh_token')
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception:
                # Token was already invalid, just continue to delete cookies
                pass

        # Delete the cookies from the browser
        res.delete_cookie('access_token')
        res.delete_cookie('refresh_token')
        return res
        
# change password >    
class SendOTPCP(APIView):
    authentication_classes = []  # No authentication needed for this view
    permission_classes = [AllowAny]

    # sends otp for changing password
    # different from SendOtp as it verifies the user's email before sending the OTP

    def post(self, request):
        try:
            email = request.data.get('email')
            logger.info(f"Received email verification request for: {email}")

            if not User.objects.filter(email=email).exists():
                logger.warning(f"Email not found: {email}")
                return Response(
                    {
                        "status": False,
                        "message": "Email not found. check the email or register now.",
                        "data": {}
                    }
                )

            if tries := cache.get(f"blocked:{email}"):
                if tries > 5:
                    logger.warning(f"OTP request throttled for: {email}")
                    return Response(
                        {
                            "status": False,
                            "message": "You have used all your retries, Please come back after a day.",
                            "data": {}
                        }
                    )

            generate_otp(email)
            otp = cache.get(f"otp:{email}")
            plain_message = (
                f"Hi there,\n\n"
                f"You recently requested a One-Time Password (OTP) to verify your email address.\n\n"
                f"Your OTP is: {otp}\n\n"
                f"This code is valid for the next 10 minutes. Please do not share this with anyone. "
                f"If you did not request this OTP, please ignore this email.\n\n"
                f"Thank you,\n"
                f"The ChatNForm"
            )
            send_otp(
                    subject="OTP for email verification.",
                    message=plain_message,
                    email=email
                )
            logger.info(f"Sent OTP email to: {email}")

            return Response(
                {
                    "status": True,
                    "message": "otp sent.",
                    "data": {
                        "verified": False
                    }
                }
            )
        except Exception as e:
            logger.error(f"Exception in VerifyEmail GET: {e}", exc_info=True)
            return Response(
                {
                    "status": False,
                    "message": "something went wrong",
                    "data": {}
                },
            )


class VarifyToCP(APIView):
    authentication_classes = []  # No authentication needed for this view
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = request.data.get("email")
            otp = request.data.get("otp")
            if varify_otp(email=email, otp=otp):
                cache.set(f"varified:{email}", True, 60*30)
                return Response(
                    {
                        "status": True,
                        "message": "OTP varified.",
                        "data": {}
                    }
                )
            else:
                return Response(
                    {
                        "status": False,
                        "message": "incorrect or invalid otp.",
                        "data": {}
                    }
                )
        except Exception as e:
            logger.error(f"Exception in verifyEmail GET: {e}", exc_info=True)
            return Response(
                {
                    "status": False,
                    "message": "something went wrong",
                    "data": {}
                }
            )


class ChangePassword(APIView):
    authentication_classes = []  # No authentication needed for this view
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data
            email = data.get("email")
            if cache.get(f"varified:{email}"):
                user = User.objects.get(email=email)
                new_password = data.get("new_password")
                if new_password:
                    if validate_new_passsword(new_password):
                        user.set_password(new_password)
                        user.save()
                        return Response(
                            {
                                "status": True,
                                "message": "password changed successfully.",
                                "data": {}
                            }
                        )
                    return Response(
                        {
                            "status": False,
                            "message": "Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.",
                            "data": {}
                        }
                    )
                return Response(
                        {
                            "status": False,
                            "message": "New password not recived.",
                            "data": {}
                        }
                    )

            return Response(
                {
                    "status": False,
                    "message": "change password session expired. try again.",
                    "data": {}
                }
            )

        except Exception as e:
            logger.error(f"Exception in verifyEmail GET: {e}", exc_info=True)
            return Response(
                {
                    "status": False,
                    "message": "something went wrong.",
                    "data": {}
                }
            )


# My Account
class MyAccount(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get(self, request):
        try:
            queryset = User.objects.get(pk=request.user.pk)
            serializer = CNFUserSerializer(queryset)
            return Response(
                {
                    'status': True,
                    'message': 'User returned.',
                    'data': {
                        "user": serializer.data
                    }
                }
            )

        except User.DoesNotExist:
            return Response(
                {
                    'status': False,
                    'message': 'user not authenticated.',
                    'data': {}
                }, status=401
            )
    
    
    def patch(self, request):
        try:
            data = request.data
            if data.get("name") or data.get("profile_image"):
                try:
                    user = User.objects.get(id=request.user.id)
                    serializer = CNFUserSerializer(instance=user, data=data, partial=True)
                    
                    if serializer.is_valid():
                        serializer.save()
                        return Response(
                            {
                                "status": True,
                                "message": "Account updated",
                                "data": serializer.data
                            }
                        )
                    return Response(
                            {
                                "status": False,
                                "message": serializer.errors,
                                "data": {}
                            }, status=400
                        )
                except User.DoesNotExist:
                    return Response(
                        {
                            "status": False,
                            "message": "User not found.",
                            "data": {}
                        }, status=404
                    )

            return Response(
                {
                    "status": False,
                    "message": "Data not updated.",
                    "data": {}
                }, status=400
            )

        except Exception as e:
            logger.error(f"Exception in verifyEmail GET: {e}", exc_info=True)
            return Response(
                {
                    "status": False,
                    "message": "something went wrong.",
                    "data": {}
                }, status=400
            )


# websocket authentication

class WebSocketTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Generate a unique, short-lived token
        temp_token = str(uuid.uuid4())
        
        # Store the token in Django's cache with a short expiration time (e.g., 10 seconds)
        cache.set(temp_token, request.user.id, timeout=100)

        return Response({
            'status': True,
            'message': 'WebSocket token generated.',
            'data': {'token': temp_token}
        })
