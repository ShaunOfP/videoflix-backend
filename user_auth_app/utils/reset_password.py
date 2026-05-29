from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


def send_reset_mail(email, reset_link):
    """
    Sends a mail to rest the password.
    """
    email_template = render_to_string(
        "pw_reset.html",
        {
            "mail": email,
            "reset_link": reset_link
        }
    )

    mail_content = EmailMultiAlternatives(
        subject="Reset your Password",
        body=email_template,
        from_email="noreply@videoflix.com",
        to=[email]
    )

    mail_content.attach_alternative(email_template, "text/html")
    mail_content.send()
