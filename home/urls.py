from django.urls import path
from home.views import GetCSRFToken


urlpatterns = [
    path('get-csrf-token/', GetCSRFToken.as_view())
]
