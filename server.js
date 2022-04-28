const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const csurf = require('csurf');
const csrfProtection = csurf({ cookie: { httpOnly: true } });
const cors = require('cors');

const server = jsonServer.create();
const database = jsonServer.router('./database.json');
const db = () => JSON.parse(fs.readFileSync('./database.json', 'UTF-8'));
const refreshTokensDb = () => JSON.parse(fs.readFileSync('./refreshTokens.json', 'UTF-8'));

const { accessTokenConfig, refreshTokenConfig } = require('./config');

server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(cookieParser());
server.use(jsonServer.defaults());
server.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true,
  })
);
server.use(csrfProtection);

const saveRefreshToken = (oldToken = '', newToken = '', payload) => {
  fs.readFile('./refreshTokens.json', (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }
    data = JSON.parse((data ?? { refreshTokens: {} }).toString());
    const tokenData = data[oldToken];
    if (tokenData) {
      delete data[oldToken];
    }
    data[newToken] = payload;

    console.log('writeFile for refreshTokens', data);
    fs.writeFile('./refreshTokens.json', JSON.stringify(data), (err, result) => {
      // WRITE
      if (err) {
        const status = 401;
        const message = err;
        res.status(status).json({ status, message });
        return;
      }
    });
  });
};

const findUserById = (id) => {
  const current = db().users.find((user) => user.id.toString() === id.toString());
  if (current) {
    const { password, ...rest } = current;
    return rest;
  }
};

const currentUser = ({ email, password }) => {
  const current = db().users.find((user) => user.email === email && user.password === password);
  if (current) {
    const { password, ...rest } = current;
    return rest;
  }
};

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  return !!currentUser({ email, password });
}

const createUserIdCookie = (res, userId) => {
  res.cookie('userId', userId, {
    maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
  });
};

const verifyToken = (token, secretKey) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, secretKey, (err, decode) => {
      if (err) {
        reject(err);
      }
      resolve(decode);
    });
  });
};

const createAccessToken = (res, payload) => {
  const token = jwt.sign({ email: payload.email }, accessTokenConfig.secretKey, {
    expiresIn: accessTokenConfig.expiresIn,
  });
  res.cookie(accessTokenConfig.name, `Bearer ${token}`, {
    maxAge: 1 * 60 * 60 * 1000, // 1 hour
    httpOnly: true,
    //secure: true; for ssl (if any)
    sameSite: 'strict', // Using for browsers support this property.
  });
  return token;
};

const createRefreshToken = (res, payload, oldRefreshToken = '') => {
  const newRefreshToken = jwt.sign({ email: payload.email }, refreshTokenConfig.secretKey, {
    expiresIn: refreshTokenConfig.expiresIn,
  });

  saveRefreshToken(oldRefreshToken, newRefreshToken, { email: payload.email });
  res.cookie(refreshTokenConfig.name, newRefreshToken, {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    httpOnly: true,
    sameSite: 'strict', // Using for browsers support this property.
  });
  return newRefreshToken;
};

const generateAccessAndRefreshToken = (res, payload) => {
  const accessToken = createAccessToken(res, payload);
  const refreshToken = createRefreshToken(res, payload);

  console.log('Access Token:' + accessToken);
  console.log('Refresh Token:' + refreshToken);

  return {
    accessToken,
    refreshToken,
  };
};

// Register New User
server.post('/auth/register', (req, res) => {
  console.log('register endpoint called; request body:');
  console.log(req.body);
  const { email, password } = req.body;

  if (isAuthenticated({ email, password })) {
    const status = 401;
    const message = 'Email and Password already exist';
    res.status(status).json({ status, message });
    return;
  }

  fs.readFile('./database.json', (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    // Get current users data
    data = JSON.parse(data.toString());

    // Get the id of last user
    const lastItemId = data.users[data.users.length - 1].id;

    //Add new user
    data.users.push({ id: lastItemId + 1, email: email, password: password }); //add some data

    // Save user id to cookie
    createUserIdCookie(res, lastItemId + 1);

    fs.writeFile('./database.json', JSON.stringify(data), (err, result) => {
      // WRITE
      if (err) {
        const status = 401;
        const message = err;
        res.status(status).json({ status, message });
        return;
      }
    });
  });

  // Create token for new user
  generateAccessAndRefreshToken(res, { email, password });

  res.status(200).json({ user: currentUser({ email, password }) });
});

// Login to one of the users from ./users.json
server.post('/auth/login', (req, res) => {
  console.log('login endpoint called; request body:');
  console.log(req.body);

  const { email, password } = req.body;

  console.log('email:', email);
  console.log('password:', password);

  if (!isAuthenticated({ email, password })) {
    const status = 401;
    const message = 'Incorrect email or password';
    res.status(status).json({ status, message });
    return;
  }

  const current = currentUser({ email, password });
  createUserIdCookie(res, current.id);

  generateAccessAndRefreshToken(res, { email, password });
  res.status(200).json(current);
});

server.post('/auth/refreshToken', async (req, res) => {
  const refreshToken = req.cookies[refreshTokenConfig.name];
  const refreshTokenData = refreshTokensDb().refreshTokens[refreshToken ?? ''];

  if (!refreshTokenData) {
    const status = 401;
    const message = 'Invalid refresh token';
    res.status(status).json({ status, message });
    return;
  }

  try {
    await verifyToken(refreshToken, refreshTokenConfig.secretKey);

    createAccessToken(res, { email: refreshTokenData.email });
    createRefreshToken(res, { email: refreshTokenData.email }, refreshToken);

    res.status(200).json({ isRefreshed: true });
  } catch (error) {
    const status = 401;
    const message = 'Invalid refresh token';
    res.status(status).json({ status, message, error });
  }
});

server.get('/csrfToken', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ========================== Check Auth for API ==========================

server.use(/^(?!\/auth).*$/, async (req, res, next) => {
  const accessToken = req.cookies[accessTokenConfig.name];
  console.log('🚀 ~ file: server.js ~ line 252 ~ server.use ~ accessToken', accessToken);

  try {
    await verifyToken(accessToken.split(' ')[1], accessTokenConfig.secretKey);
    next();
  } catch (error) {
    const status = 401;
    const message = 'Invalid access token.';
    res.status(status).json({ status, message, error });
  }
});

server.get('/me', (req, res) => {
  const { userId = '' } = req.cookies;
  const user = findUserById(userId);

  if (!user) {
    const status = 401;
    const message = 'This user does not exist.';
    res.status(status).json({ status, message });
    return;
  }

  res.status(200).json(user);
});

server.post('/auth/logout', (req, res) => {
  res.clearCookie(accessTokenConfig.name);
  res.clearCookie(refreshTokenConfig.name);
  res.clearCookie('userId');
  res.status(200).json(true);
});

server.post('/test-csrf', (req, res) => {
  res.status(200).json(true);
});

// Handle CSRF attack error.
server.use((err, req, res, next) => {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);

  res.status(403);
  res.send('CSRF attack detected!');
});

server.use(database);

server.listen(8000, () => {
  console.log('Run Auth API Server');
});
