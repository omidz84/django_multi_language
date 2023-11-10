from .models import User
from rest_framework.test import APITestCase


class LoginUserSerializerTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create(
            phone_number='01234567890',
            code_melli='1234567890',
            address='yazd',
            location='{"type": "Point", "coordinates": [30.0, 10.0]}',
            password='password'
        )

    def test_valid_login(self):
        data = {
            'phone_number': '01234567890',
            'password': 'password'
        }
        response = self.client.post('api/user/login/', data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('user', response.data)
        self.assertIn('token', response.data)
        self.assertIn('access', response.data['token'])
        self.assertIn('refresh', response.data['token'])

    def test_invalid_login(self):
        data = {
            'phone_number': '123456789',
            'password': 'wrong_password'
        }
        response = self.client.post('api/user/login/', data)
        self.assertEqual(response.status_code, 400)
        self.assertIn('msg', response.data)
