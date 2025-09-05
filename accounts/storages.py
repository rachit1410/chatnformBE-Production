import mimetypes
from django.core.files.storage import Storage
from django.conf import settings
from supabase import create_client

class SupabaseStorage(Storage):
    def __init__(self):
        self.supabase = create_client(
            settings.SUPABASE_URL,
            settings.SUPABASE_KEY
        )
        self.bucket = settings.SUPABASE_BUCKET

    def _save(self, name, content):
        mime, _ = mimetypes.guess_type(name)
        self.supabase.storage.from_(self.bucket).upload(
            path=name,
            file=content,
            file_options={"content-type": mime or "application/octet-stream"}
        )
        return name

    def url(self, name):
        return f"{settings.MEDIA_URL}{name}"

    def exists(self, name):
        res = self.supabase.storage.from_(self.bucket).list(path=name)
        return len(res) > 0
