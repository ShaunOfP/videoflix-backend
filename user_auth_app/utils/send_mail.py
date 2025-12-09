from django.core.mail import send_mail

def send_activation_mail(email, activation_link):
    """
    Configures and sends the mail.
    """
    send_mail(
        subject="Activate your account",
        message=f"Click the link to activate your account: {activation_link}",
        from_email="noreplay@videoflix.com",
        recipient_list=[email]
    )