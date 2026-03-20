from django.db import models

# Create your models here.
class Video(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    thumbnail_url = models.URLField(max_length=500, blank=True, null=True)
    category = models.CharField(max_length=255, blank=True, null=True)
    video_file = models.FileField(upload_to='videos/')

    def __str__(self):
        return self.title