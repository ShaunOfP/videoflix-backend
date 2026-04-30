import os
import django_rq
from django.dispatch import receiver
from django.db.models.signals import post_save, post_delete

from video_management_app.tasks import convert_480p, convert_720p, convert_1080p
from .models import Video


@receiver(post_save, sender=Video)
def video_post_save(sender, instance, created, **kwargs):
    """
    When a new video is created, this will convert the video to 480p, 720p, and 1080p formats.
    """
    if created:
        queue = django_rq.get_queue('default', autocommit=True)
        queue.enqueue(convert_480p, instance.video_file.path, instance.id)
        queue.enqueue(convert_1080p, instance.video_file.path, instance.id)
        queue.enqueue(convert_720p, instance.video_file.path, instance.id)


@receiver(post_delete, sender=Video)
def video_post_delete(sender, instance, **kwargs):
    """
    Deletes file from filesystem
    when corresponding `Video` object is deleted.
    """
    if instance.video_file:
        if os.path.isfile(instance.video_file.path):
            os.remove(instance.video_file.path)
