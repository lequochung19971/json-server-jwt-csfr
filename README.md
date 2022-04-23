# JSONServer + JWT Auth + CSRF

A Fake REST API using json-server with JWT authentication and prevent XSS and CSFR attacks 

## Features
- Login
- Register
- Refresh Token
- Prevent XSS and CSFR acttacks

## Diagram
![authorization-flow](https://user-images.githubusercontent.com/43690592/164885707-b4a75469-3f56-4abd-84c4-d85f8e0759b0.jpg)

## Install

```bash
$ npm install
$ npm run start-auth
```

## How login/register works?

When you login/register by sending a POST request to

```
POST http://localhost:8000/auth/login
POST http://localhost:8000/auth/register
```
with the following data 

```
{
  "email": "test@gmail.com",
  "password":"Test@12"
}
```

Server will save accessToken and refreshToken follow configs below into cookie with **HttpOnly**, **SameSite** options
- Configs:
  ```
  const accessTokenConfig = {
    name: '__aT',
    secretKey: 'secretKey',
    expiresIn: '10m',
  };

  const refreshTokenConfig = {
    name: '__rfT',
    secretKey: 'secretRefreshKey',
    expiresIn: '7d',
  };
  ```
Every time the client call API to access the data resources from server, the browser will automatically attach accessToken and refreshToken into the headers and send it to the server.

## Prevent XSS attack
- After every time login/register server will create/update accessToken and refreshToken into cookie with **HttpOnly** option.

## Prevent CSFR attack
- Using **SameSite** option when setting cookie to prevent CSFR attack. However, not all the browsers support this property.
- Using another way:
  - Using a middleware ([csurf](https://github.com/expressjs/csurf)) to prevent this attack.
  - Require the client call API (/csrfToken) to get **csrfToken** from the server and add to headers['X-CSRF-Token'] for every request.
