const dotenv = require('dotenv');

const env = process.env.NODE_ENV || 'development';
const isProduction = env === 'production';

if (!isProduction) {
  dotenv.config({ silent: true });
}

const port = process.env.PORT;

module.exports = {
  database: {
    url: process.env.MONGO_URL
  },
  environment: env,
  frontEndUrls: {
    clientOne: process.env.CONE_URL,
    clientTwo: process.env.CTWO_URL
  },
  mailgun: {
    sender: process.env.SENDER || 'no-reply@legalx.com',
    apiKey: process.env.MAILGUN_API_KEY,
    domain: process.env.MAILGUN_DOMAIN
  },
  maxFileSize: 2000000,
  secret: process.env.SECRET,
  port: port
};
