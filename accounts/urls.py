from django.urls import path
from accounts.views import (
    RegisterApiView,
    VerifyEmail,
    LoginApiView,
    VarifyToCP,
    ChangePassword,
    SendOTP,
    MyAccount,
    SendOTPCP,
    TokenRefreshView,
    WebSocketTokenView
)

urlpatterns = [
    path("register/", RegisterApiView.as_view()),
    path("send-otp/", SendOTP.as_view()),
    path("verify-email/", VerifyEmail.as_view()),
    path("jwt/", LoginApiView.as_view()),
    path("me/", MyAccount.as_view()),
    path("forgot-password/", SendOTPCP.as_view()),
    path('varify-otp/', VarifyToCP.as_view()),
    path('change-password/', ChangePassword.as_view()),
    path('refresh/', TokenRefreshView.as_view()),
    path('ws-token/', WebSocketTokenView.as_view()),
]
