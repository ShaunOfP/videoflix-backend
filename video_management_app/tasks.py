import subprocess


def convert_480p(source):
    """
    Converts the video into 480p resolution
    """
    target = source + '_480p.mp4'
    cmd = ['ffmpeg', '-i', source, '-s', 'hd480', '-c:v', 'libx264',
           '-crf', '23', '-c:a', 'aac', '-strict', '-2', target]
    subprocess.run(cmd)


def convert_720p(source):
    """
    Converts the video into 720p resolution
    """
    target = source + '_720p.mp4'
    cmd = ['ffmpeg', '-i', source, '-s', 'hd720', '-c:v', 'libx264',
           '-crf', '23', '-c:a', 'aac', '-strict', '-2', target]
    subprocess.run(cmd)


def convert_1080p(source):
    """
    Converts the video into 1080p resolution
    """
    target = source + '_1080p.mp4'
    cmd = ['ffmpeg', '-i', source, '-s', 'hd1080', '-c:v', 'libx264',
           '-crf', '23', '-c:a', 'aac', '-strict', '-2', target]
    subprocess.run(cmd)
