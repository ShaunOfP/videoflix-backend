# Videoflix

Videoflix is a Netflix clone made for training purposes.

This repository contains the backend for the Videoflix-Project. The Frontend is provided by the Developer Akademie and can be found here: https://github.com/Developer-Akademie-Backendkurs/project.Videoflix

## Installation

Clone the repository to your computer via git bash.

```bash
git clone https://github.com/ShaunOfP/videoflix-backend.git
```
A detailed guide to cloning a repository can be found [here](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository).

## Usage
Open the project in your Code editor and open the Terminal for the project.


Use the package manager [pip](https://pypi.org/project/pip/#files) to install the dependencies.

```bash
pip install -r requirements.txt
```

Create a virtual environment in the project folder
```bash
python -m venv env
```

Then start a virtual environment.
```bash
#Windows
.\env\Scripts\Activate

#Unix
source .env/bin/activate
```

If you want to test this repository without a frontend you need to have software like [Postman](https://www.postman.com/downloads/).

## Configuration
Before you can use the Project it is import that your docker container is configured and running.

A detailed guide on how to set it up can be found [here](https://github.com/Developer-Akademie-Backendkurs/material.videoflix-docker-files).

# Endpoints
The Endpoints are split into two groups:
1. Authentication, for registration and login purposes
2. Video, for video storage

## 1.1 Registration
To use the project you first have to create a user.

Endpoint: localhost/api/register/

HTTP-Method: POST

Request body:
```bash
{
  "email": "user@example.com",
  "password": "securepassword",
  "confirmed_password": "securepassword"
}
```
Afterwards you will receive an email to the provided mail adress where you have to activate your account in order to use it. 

## 1.2 Login
Make sure you have activated your account via the received mail.

Endpoint: localhost/api/login/

HTTP-Method: POST

Request body:
```bash
{
  "email": "user@example.com",
  "password": "securepassword"
}
```

This process will set an access and a refresh token.

## 1.3 Logout
Endpoint: localhost/api/logout/

HTTP-Method: POST

After logging out the current access and refresh token will be deleted.

You will need an active refresh token to use this endpoint.

## 1.4 
Endpoint: localhost/api/token/refresh/

HTTP-Method: POST

You will need an active refresh token to use this endpoint.

This will set a new access token.

## 1.5 Reset password
Endpoint: localhost/api/password_reset/

HTTP-Method: POST

Request body:
```bash
{
  "email": "user@example.com"
}
```

This will send an email to the provided mail adress in which you can choose a new password.

## 2.1 Video list
Endpoint: localhost/api/video/

HTTP-Method: GET

This will display a list of all videos in the database.
To use this endpoint you need to be JWT authenticated.

To authenticate you need to have a Bearer with the access token as value.

This can be done under the Headers tab in Postman.

Choose "Authorization" as Key and "Bearer access_cookie-value" as Value. Note: between Bearer and the access_cookie-value is a whitespace, also replace the access_cookie-value with the actual cookie value (found under the send button when clicked on the cookies button)

## Contributing
It is not intended to contribute to this repository.
## License
[MIT](https://choosealicense.com/licenses/mit/)