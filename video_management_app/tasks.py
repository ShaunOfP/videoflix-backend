import os
import subprocess
from core import settings


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
