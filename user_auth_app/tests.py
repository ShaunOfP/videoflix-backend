from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework.test import APIClient, APITestCase
from unittest.mock import patch


TEST_PASSWORD = 'testpassword1'


class UserAuthTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser1',
            email='testuser1@example.com',
            password=TEST_PASSWORD,
            is_active=True
        )

    @patch('user_auth_app.api.views.django_rq.get_queue')
    def test_user_registration(self, mock_queue):
        mock_queue.return_value.enqueue.return_value = None

        url = reverse('user-registration')
        data = {
            'email': 'testuser@example.com',
            'password': 'testpassword',
            'confirmed_password': 'testpassword'
        }

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 201)

    def test_user_login(self):
        login_url = reverse('user-login')
        login_data = {
            'email': self.user.email,
            'password': TEST_PASSWORD
        }
        response = self.client.post(login_url, login_data)
        self.assertEqual(response.status_code, 200)

    def test_user_logout(self):
        login_url = reverse('user-login')
        login_data = {
            'email': self.user.email,
            'password': TEST_PASSWORD
        }
        response = self.client.post(login_url, login_data)
        self.assertEqual(response.status_code, 200)

        logout_url = reverse('user-logout')
        response = self.client.post(logout_url)
        self.assertEqual(response.status_code, 200)

    @patch("user_auth_app.api.views.django_rq.get_queue")
    def test_password_reset(self, mock_queue):
        mock_queue.return_value.enqueue.return_value = None

        url = reverse('password-reset')

        response = self.client.post(url, {
            'email': self.user.email
        })
        self.assertEqual(response.status_code, 200)

    def test_password_confirm(self):
        user = self.user
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        url = reverse('password-confirm',
                      kwargs={'uidb64': uid, 'token': token})

        data = {
            "new_password": 'newsecurepassword',
            "confirm_password": 'newsecurepassword'
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 200)
