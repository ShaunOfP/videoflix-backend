from django.db import models


class Video(models.Model):
    """Model representing a video uploaded by a user."""
    CATEGORY_CHOICES = [
        ('Action', 'Action'),
        ('Comedy', 'Comedy'),
        ('Drama', 'Drama'),
        ('Horror', 'Horror'),
        ('Sci-Fi', 'Sci-Fi'),
        ('Documentary', 'Documentary'),
        ('Uncategorized', 'Uncategorized'),
    ]

    created_at = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    thumbnail_url = models.ImageField(
        upload_to='thumbnails/', null=True, blank=True)
    category = models.CharField(
        max_length=255, choices=CATEGORY_CHOICES, default='Uncategorized')
    video_file = models.FileField(upload_to='videos/')

    def __str__(self):
        return self.title
