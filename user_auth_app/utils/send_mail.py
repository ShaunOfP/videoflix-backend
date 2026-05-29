from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from email.mime.image import MIMEImage


def send_activation_mail(user, activation_link):
    """
    Configures and sends the mail.
    """
    email_template = render_to_string(
        "activation.html",
        {
            "username": user.username,
            "activation_link": activation_link
        }
    )

    mail_content = EmailMultiAlternatives(
        subject="Confirm your email",
        body=email_template,
        from_email="noreply@videoflix.com",
        to=[user.email]
    )

    mail_content.attach_alternative(email_template, "text/html")

    with open("static/images/Logo.png", "rb") as logo_file:
        img = MIMEImage(logo_file.read())
        img.add_header("Content-ID", "<logo>")
        img.add_header("Content-Disposition", "inline")
        mail_content.attach(img)
    mail_content.send()
