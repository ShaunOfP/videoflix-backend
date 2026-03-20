from rest_framework import serializers

from video_management_app.models import Video


class VideoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Video
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'title',
                            'description', 'thumbnail_url', 'category']
