from django.apps import AppConfig


class VideoManagementAppConfig(AppConfig):
    name = 'video_management_app'

    def ready(self):
        import video_management_app.signals
