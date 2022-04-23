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

module.exports = { accessTokenConfig, refreshTokenConfig };
