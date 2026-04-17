from django.apps import AppConfig


class VideoManagementAppConfig(AppConfig):
    name = 'video_management_app'

    def ready(self):
        """
        This method is called when the app is ready.
        It imports the signals module to ensure that signal handlers are registered.
        """
        import video_management_app.signals
