from django.urls import path
from searching.views import SearchUserAPI, SearchGroupAPI

urlpatterns = [
    path('user/', SearchUserAPI.as_view(), name='user'),
    path('group/', SearchGroupAPI.as_view(), name='group'),
]
