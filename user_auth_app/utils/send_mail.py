from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


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
    mail_content.send()
