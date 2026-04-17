from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated

from video_management_app.api.serializers import VideoSerializer
from video_management_app.models import Video

class VideoListView(ListAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Video.objects.all()
    serializer_class = VideoSerializer


class VideoDetailView(RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Video.objects.all()
    serializer_class = VideoSerializer


class VideoSegmentView(RetrieveAPIView):
    permission_classes = [IsAuthenticated]