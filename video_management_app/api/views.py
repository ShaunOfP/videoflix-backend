import os

from django.http import FileResponse, StreamingHttpResponse
from django.views import View
from rest_framework.generics import Http404, ListAPIView

from core import settings
from user_auth_app.api.permissions import IsAuthenticatedWithAccessToken

from video_management_app.api.serializers import VideoSerializer
from video_management_app.models import Video


class VideoListView(ListAPIView):
    """
    Returns a list of all videos in the database.
    """
    permission_classes = [IsAuthenticatedWithAccessToken]
    queryset = Video.objects.all()
    serializer_class = VideoSerializer


class VideoDetailView(View):
    """
    Returns the Index.m3u8 playlist for a given video and resolution.
    """

    def get(self, request, *args, **kwargs):
        movie_id = self.kwargs['movie_id']
        resolution = self.kwargs['resolution']

        path = os.path.join(
            settings.MEDIA_ROOT,
            'videos',
            str(movie_id),
            resolution,
            'index.m3u8'
        )

        if not os.path.exists(path):
            raise Http404('Playlist not found')

        def file_iterator(file_path):
            with open(file_path, 'rb') as f:
                yield from f

        return StreamingHttpResponse(
            file_iterator(path),
            content_type='application/vnd.apple.mpegurl'
        )


class VideoSegmentView(View):
    """
    Serves the HLS segments for a given video and resolution.
    """

    def get(self, request, *args, **kwargs):
        movie_id = self.kwargs['movie_id']
        resolution = self.kwargs['resolution']
        segment = self.kwargs['segment']

        path = os.path.join(
            settings.MEDIA_ROOT,
            'videos',
            str(movie_id),
            resolution,
            segment
        )

        if not os.path.exists(path):
            raise Http404('Segment not found')

        def file_iterator(file_path):
            with open(file_path, 'rb') as f:
                yield from f

        return StreamingHttpResponse(
            file_iterator(path),
            content_type='video/MP2T'
        )
