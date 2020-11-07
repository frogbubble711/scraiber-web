# SCRAIBER-WEB BACKEND

Scraiber-Web backend with Node.js, MongoDB

## Install

npm install
nodemon

## Run the app

    node app.js

# REST API

The REST API to the example app is described below.

## Create a new User via Email.

### Request

`POST /register`

    http://localhost:5000/api/register

    {
        firstName: "",
        lastName: "",
        email: "",
        password: "",
        password_confirm: ""
    }

### Response

    {
        statue: 'success',
        msg: `A verification email has been sent to user.email.`
    }
    You need to check the email.
    Token will be sent via email.

## Confirm Email address

### Request

`POST /confirmation`

    http://localhost:5000/api/confirmation

    {
        token: ""
    }

### Response

    {
        msg: 'The account has been verified. Please log in.' 
    }

## Login via Email

### Request

`POST /login`

    http://localhost:5000/api/login

    {
        email: "",
        password: ""
    }

### Response

    {
        success: true,
        token: token,
        user: {
            id: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            avatar: user.avatar
        }
    }

## Login with Google

### Request

`POST /googlelogin`

    http://localhost:5000/api/googlelogin

    {
        tokenId: ""
    }

### Response

    {
        success: true,
        token: token,
        user: {
            id: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            avatar: user.avatar
        }
    }

## Login with Facebook

### Request

`POST /facebooklogin`

    http://localhost:5000/api/facebooklogin

    {
        accessToken: "",
        userID: ""
    }

### Response

    {
        success: true,
        token: token,
        user: {
            id: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            avatar: user.avatar
        }
    }

## Forgot Password

### Request

`POST /forgotpassword`

    http://localhost:5000/api/forgotpassword

    {
        email: ""
    }

### Response

    {
        statue: 'success',
        msg: `A verification email has been sent to user.email.`
    }
    
## Reset Password

### Request

`POST /reset-password`

    http://localhost:5000/api/reset-password

    {
        token: ""
    }

### Response

    {
        msg: 'Password Update Successfully!' 
    }
