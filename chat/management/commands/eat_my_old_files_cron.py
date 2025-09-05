from django.core.management.base import BaseCommand
from django.utils import timezone
from chat.models import File
import os

class Command(BaseCommand):
    help = "Delete expired files from File model"

    def add_arguments(self, parser):
        parser.add_argument(
            "--hours",
            type=int,
            default=24 * 5,
            help="Delete files older than this many hours (default: 120)"
        )

    def handle(self, *args, **options):
        lifetime_hours = options["hours"]
        cutoff = timezone.now() - timezone.timedelta(hours=lifetime_hours)
        expired_files = File.objects.filter(created_at__lt=cutoff)

        count = 0
        for f in expired_files:
            try:
                file_path = f.file.path
                if os.path.exists(file_path):
                    os.remove(file_path)
                f.delete()
                count += 1
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Failed to delete {f.file}: {e}"))

        self.stdout.write(self.style.SUCCESS(f"Deleted {count} expired files"))
