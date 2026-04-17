from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated

from video_management_app.api.serializers import VideoSerializer
from video_management_app.models import Video

class VideoListView(ListAPIView):
    """
    Returns a list of all videos in the database.
    """
    permission_classes = [IsAuthenticated]
    queryset = Video.objects.all()
    serializer_class = VideoSerializer