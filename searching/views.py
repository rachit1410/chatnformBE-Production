from rest_framework.views import APIView
from searching.documents import UserDocument, GroupDocument
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated


class SearchUserAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.GET.get("q")
        data = []
        s = UserDocument.search().filter("match", name=query)

        for hit in s:
            if not hit.id == request.user.pk:
                data.append({
                    'id': hit.id,
                    'name': hit.name
                })

        return Response(
            {
                'status': True,
                'message': 'Info: Search results fetched.',
                'data': data
            }
        )


class SearchGroupAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.GET.get("g")
        data = []
        s = GroupDocument.search().filter("match", group_name=query)

        for hit in s:
            if not hit.group_owner.id == request.user.id:
                data.append({
                    "uid": hit.uid,
                    "group_name": hit.group_name,
                    "group_type": hit.group_type,
                    "group_owner": {
                        "id": hit.group_owner.id,
                        "name": hit.group_owner.name,
                    },
                    "group_profile": {
                        "image": hit.group_profile.image,
                    }
                })
        
        return Response(
            {
                'status': True,
                'message': 'Search results fetched.',
                'data': data
            }
        )
