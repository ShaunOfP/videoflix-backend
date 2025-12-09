from django.core.mail import send_mail


def send_reset_mail(email, reset_link):
    """
    Sends a mail to rest the password.
    """
    send_mail(
        subject="Reset your password",
        message=f"Click the link to reset your password: {reset_link}",
        from_email="noreply@videoflix.com",
        recipient_list=[email]
    )
