# your_app/auth.py

from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
import urllib.parse

@database_sync_to_async
def get_user(token):
    """
    Retrieves and invalidates a user based on a temporary token from the cache.
    """
    user_id = cache.get(token)
    if user_id:
        try:
            user = get_user_model().objects.get(id=user_id)
            # Invalidate the token immediately after use
            cache.delete(token)
            return user
        except get_user_model().DoesNotExist:
            return AnonymousUser()
    return AnonymousUser()

class TokenAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        try:
            # Decode the query string to get all parameters
            query_string = scope.get('query_string', b'').decode('utf-8')
            query_params = urllib.parse.parse_qs(query_string)

            # Get the temporary token and group ID from the parsed query parameters
            # parse_qs returns a list for each key, so we take the first element
            temp_token = query_params.get('token', [None])[0]
            group_id = query_params.get('group', [None])[0]

            # Set the user and group_id in the scope for the consumer to use
            if temp_token:
                scope['user'] = await get_user(temp_token)
            else:
                scope['user'] = AnonymousUser()
                
            scope['group_id'] = group_id
            
        except Exception as e:
            # Handle any decoding or parsing errors
            print(f"Error in TokenAuthMiddleware: {e}")
            scope['user'] = AnonymousUser()
            scope['group_id'] = None

        return await self.app(scope, receive, send)
