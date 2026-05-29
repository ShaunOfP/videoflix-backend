from email.mime.image import MIMEImage

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
    with open("static/images/Logo.png", "rb") as logo_file:
        img = MIMEImage(logo_file.read())
        img.add_header("Content-ID", "<logo>")
        img.add_header("Content-Disposition", "inline")
        mail_content.attach(img)
    mail_content.send()
