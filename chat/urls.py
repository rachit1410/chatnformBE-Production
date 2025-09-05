from django.urls import path
from chat.views import (
    CreateGroupAPI,
    ListGroupsAPI,
    MemberAPI,
    MessageAPI,
    RefreshApi,
    DeleteMessageApi,
    RequestApiView,
    FileUpload,
    ClearAllMessages
)

urlpatterns = [
    path("group/", CreateGroupAPI.as_view()),
    path("list-groups/", ListGroupsAPI.as_view()),
    path("members/", MemberAPI.as_view()),
    path("messages/", MessageAPI.as_view()),
    path("custom-refresh/", RefreshApi.as_view()),
    path("message/delete/<uuid:pk>/", DeleteMessageApi.as_view()),
    path("join-requests/", RequestApiView.as_view()),
    path("file-upload/", FileUpload.as_view()),
    path("clear-all-messages/", ClearAllMessages.as_view()),
]
