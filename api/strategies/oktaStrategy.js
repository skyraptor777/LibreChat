const { Strategy: OktaStrategy } = require('passport-okta-oauth');
const { createNewUser, handleExistingUser } = require('./process');
const { logger } = require('~/config');
const User = require('~/models/User');

const oktaLogin = async (accessToken, refreshToken, profile, cb) => {
  try {
    const email = profile.emails[0].value;
    const oktaId = profile.id;
    const oldUser = await User.findOne({ email });
    const ALLOW_SOCIAL_REGISTRATION =
      process.env.ALLOW_SOCIAL_REGISTRATION?.toLowerCase() === 'true';
    const avatarUrl = profile.photos[0].value;

    if (oldUser) {
      await handleExistingUser(oldUser, avatarUrl);
      return cb(null, oldUser);
    }

    if (ALLOW_SOCIAL_REGISTRATION) {
      const newUser = await createNewUser({
        email,
        avatarUrl,
        provider: 'okta',
        providerKey: 'oktaId',
        providerId: oktaId,
        username: profile.username,
        name: profile.displayName,
        emailVerified: profile.emails[0].verified,
      });
      return cb(null, newUser);
    }
  } catch (err) {
    logger.error('[oktaLogin]', err);
    return cb(err);
  }
};

module.exports = () =>
  new OktaStrategy(
    {
      clientID: process.env.OKTA_CLIENT_ID,
      clientSecret: process.env.OKTA_CLIENT_SECRET,
      callbackURL: `${process.env.DOMAIN_SERVER}${process.env.OKTA_CALLBACK_URL}`,
      proxy: false,
      scope: ['user:email'],
    },
    oktaLogin,
  );
