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


def convert_360p(source):
    """
    Converts the video into 360p resolution
    """
    target = source + '_360p.mp4'
    cmd = ['ffmpeg', '-i', source, '-s', 'hd360', '-c:v', 'libx264',
           '-crf', '23', '-c:a', 'aac', '-strict', '-2', target]
    subprocess.run(cmd)
