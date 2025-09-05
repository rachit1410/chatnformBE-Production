from django.urls import path, include


urlpatterns = [
    path("auth/", include("accounts.urls")),
    path("chat/", include("chat.urls")),
    path('', include('home.urls')),
    path('search/', include('searching.urls')),
]
