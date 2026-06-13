import os
from pathlib import Path
import subprocess

from click import File
from core import settings
from video_management_app.models import Video


def convert_480p(source, video_id):
    """
    Converts the video into 480p resolution
    """
    output_dir = os.path.join(
        settings.MEDIA_ROOT,
        'videos',
        str(video_id),
        '480p'
    )
    os.makedirs(output_dir, exist_ok=True)
    target = os.path.join(output_dir, 'index.m3u8')

    cmd = [
        'ffmpeg',
        '-i', source,
        '-vf', 'scale=-2:480',
        '-c:v', 'libx264',
        '-crf', '23',
        '-c:a', 'aac',
        '-start_number', '0',
        '-hls_time', '10',
        '-hls_list_size', '0',
        '-hls_segment_filename', os.path.join(output_dir, 'segment_%03d.ts'),
        '-f', 'hls',
        target
    ]
    subprocess.run(cmd, check=True)


def convert_720p(source, video_id):
    """
    Converts the video into 720p resolution
    """
    output_dir = os.path.join(
        settings.MEDIA_ROOT,
        'videos',
        str(video_id),
        '720p'
    )
    os.makedirs(output_dir, exist_ok=True)
    target = os.path.join(output_dir, 'index.m3u8')

    cmd = [
        'ffmpeg',
        '-i', source,
        '-vf', 'scale=-2:720',
        '-c:v', 'libx264',
        '-crf', '23',
        '-c:a', 'aac',
        '-start_number', '0',
        '-hls_time', '10',
        '-hls_list_size', '0',
        '-hls_segment_filename', os.path.join(output_dir, 'segment_%03d.ts'),
        '-f', 'hls',
        target
    ]
    subprocess.run(cmd, check=True)


def convert_1080p(source, video_id):
    """
    Converts the video into 1080p resolution
    """
    output_dir = os.path.join(
        settings.MEDIA_ROOT,
        'videos',
        str(video_id),
        '1080p'
    )
    os.makedirs(output_dir, exist_ok=True)
    target = os.path.join(output_dir, 'index.m3u8')

    cmd = [
        'ffmpeg',
        '-i', source,
        '-vf', 'scale=-2:1080',
        '-c:v', 'libx264',
        '-crf', '23',
        '-c:a', 'aac',
        '-start_number', '0',
        '-hls_time', '10',
        '-hls_list_size', '0',
        '-hls_segment_filename', os.path.join(output_dir, 'segment_%03d.ts'),
        '-f', 'hls',
        target
    ]

    subprocess.run(cmd, check=True)


def generate_thumbnail(source, video_id):
    """
    Generates a thumbnail for the video.
    """
    video = Video.objects.get(id=video_id)

    thumb_name = Path(source).stem + ".jpg"
    thumb_path = Path(settings.MEDIA_ROOT) / "thumbnails" / thumb_name
    thumb_path.parent.mkdir(parents=True, exist_ok=True)

    subprocess.run([
        "ffmpeg",
        "-i", source,
        "-ss", "00:00:00.1",
        "-vframes", "1",
        "-q:v", "2",
        str(thumb_path),
    ], check=True)

    with open(thumb_path, "rb") as f:
        video.thumbnail_url.save(
            thumb_name,
            f,
            save=False
        )
    video.save(update_fields=["thumbnail_url"])
