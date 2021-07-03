const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const md5 = require('md5');
var store = require('store');
const { genJwtToken } = require('./jwt_helper');

const regex = /(\S+)\s+(\S+)/;

// Note: Express http converts all headers to lower case.
const AUTH_HEADER = 'authorization';
const BEARER_AUTH_SCHEME = 'bearer';

// Validate auth header
function parseAuthHeader(header) {
  // header = Bearer 17273746hddg773
  if (typeof header !== 'string') {
    return null;
  }
  const matches = header.match(regex);
  return (
    matches && {
      scheme: matches[1],
      value: matches[2],
    }
  );
}

// Get bearer token fron Authentication Header
const tokenFromAuthHeader = function (authScheme) {
  authScheme = authScheme.toLowerCase();
  return function (request) {
    let token = null;
    if (request.headers[AUTH_HEADER]) {
      const authParams = parseAuthHeader(request.headers[AUTH_HEADER]);
      if (authParams && authScheme === authParams.scheme.toLowerCase()) {
        token = authParams.value;
      }
    }
    return token;
  };
};


const appTokenFromRequest = tokenFromAuthHeader(BEARER_AUTH_SCHEME);

// The tokens are for validation
const intrmTokenCache = {};

// app token to validate the request is coming from the authenticated server only.
const appTokenDB = {
  sso_consumer: 'l1Q7zkOL59cRqWBkQ12ZiGVW2DBL',
  simple_sso_consumer: '1g0jJwGmRQhJwvwNOrY4i90kD0m',
};

const appPolicies = {
  sso_consumer: { role: 'admin', shareEmail: true },
  simple_sso_consumer: { role: 'user', shareEmail: false },
};

const originAppName = {
  'http://localhost:3000': 'sso_consumer',
  'http://localhost:3020': 'sso_consumer',
  'http://localhost:4200': 'simple_sso_consumer',
};

const allowedOrigins = {
  'http://localhost:4200': true,
  'http://localhost:3000': true,
  'http://localhost:3020': true,
  'http://localhost:8080': false,
};

//
const fillIntrmTokenCache = (origin, id, intrmToken) => {
  intrmTokenCache[intrmToken] = [id, originAppName[origin]];
};
//
const storeApplicationInCache = (origin, id, intrmToken) => {
  if (sessionApp[id] == null) {
    sessionApp[id] = {
      [originAppName[origin]]: true,
    };
    fillIntrmTokenCache(origin, id, intrmToken);
  } else {
    sessionApp[id][originAppName[origin]] = true;
    fillIntrmTokenCache(origin, id, intrmToken);
  }
  // console.log(
  //   {
  //     ...sessionApp,
  //   },
  //   {
  //     ...sessionUser,
  //   },
  //   {
  //     intrmTokenCache,
  //   }
  // );
};

const generatePayload = (ssoToken, req) => {
  const globalSessionToken = intrmTokenCache[ssoToken][0];
  const appName = intrmTokenCache[ssoToken][1];
  const userEmail = sessionUser[globalSessionToken];
  const user = store.get('user');
  const appPolicy = appPolicies[appName];
  const email = appPolicy.shareEmail === true ? userEmail : undefined;
  const payload = {
    ...{
      ...appPolicy,
    },
    ...{
      email,
      shareEmail: undefined,
      uid: user.userId,
      // global SessionID for the logout functionality.
      globalSessionID: globalSessionToken,
    },
  };
  return payload;
};

exports.verifySSOToken = async (req, res, next) => {
  const appToken = appTokenFromRequest(req);
  const { ssoToken } = req.query;
  // if the application token is not present or ssoToken request is invalid
  // if the ssoToken is not present in the cache some is
  // console.log(appToken, ssoToken, intrmTokenCache);
  if (
    appToken == null ||
    ssoToken == null ||
    intrmTokenCache[ssoToken] == null
  ) {
    return res.status(400).json({
      message: 'badRequest',
    });
  }

  // if the appToken is present and check if it's valid for the application
  //sso_consumer||simple_sso_consumer
  const appName = intrmTokenCache[ssoToken][1];
  //user._id
  const globalSessionToken = intrmTokenCache[ssoToken][0];
  // If the appToken is not equal to token given during the sso app registraion or later stage than invalid
  if (
    appToken !== appTokenDB[appName] ||
    sessionApp[globalSessionToken][appName] !== true
  ) {
    return res.status(403).json({
      message: 'Unauthorized',
    });
  }
  // checking if the token passed has been generated
  const payload = generatePayload(ssoToken, req);

  const token = await genJwtToken(payload);
  // delete the itremCache key for no futher use,
  delete intrmTokenCache[ssoToken];
  return res.status(200).json({
    token,
  });
};

const sessionUser = {};
const sessionApp = {};

exports.getLoginPage = (req, res, next) => {
  store.set('serviceURL', req.query.serviceURL);
  const serviceURL = req.query.serviceURL || store.get('serviceURL');
  if (serviceURL != null) {
    const url = new URL(serviceURL);
    if (allowedOrigins[url.origin] !== true) {
      return res.status(400).json({
        message: 'Your are not allowed to access the SSO Server',
      });
    }
  }
  if (req.session.user != null && serviceURL == null) {
    return res.redirect('/');
  }
  // if global session already has the user directly redirect with the token
  if (req.session.user != null && serviceURL != null) {
    const url = new URL(serviceURL);
    const intrmid = md5(req.session.user._id);
    storeApplicationInCache(url.origin, req.session.user, intrmid);
    return res.redirect(`${serviceURL}?ssoToken=${intrmid}`);
  }

  return res.render('login', {
    title: 'Login',
  });
};

exports.loginUser = (req, res, next) => {
  // Get URL of client and store in app
  const serviceURL = req.query.serviceURL || store.get('serviceURL');
  const { email, password } = req.body;

  User.findOne({
    email: email,
  }).then((user) => {
    if (user) {
      bcrypt.compare(password, user.password, function (err, isMatch) {
        if (!isMatch) {
          res.render('login', {message: 'Auth Error'});
        }
        if (isMatch) {
          store.set('user', user);
          jwt.sign(
            {
              email: email,
            },
            'secretkey',
            {
              expiresIn: '10h',
            },
            (err, token) => {
              res.cookie(
                'ssonode',
                {
                  status: true,
                  data: {
                    user: user,
                    token: token,
                  },
                },
                {
                  maxAge: 180 * 60 * 1000,
                }
              );
              req.session.user = user._id;
              sessionUser[user._id] = user.email;
              if (!serviceURL) {
                return res.redirect('/');
              }
              const url = new URL(serviceURL);
              const intrmid = md5(user._id);
              storeApplicationInCache(url.origin, user._id, intrmid);
              return res.redirect(`${serviceURL}?ssoToken=${intrmid}`);
            }
          );
        }
      });
    } else {
      res.render('login', {message: 'User does not exist'});
    }
  });
};

exports.register = (req, res, next) => {
  const { serviceURL } = req.query;
  console.log('Registering ...', req.body);
  const email = req.body.email;
  const name = req.body.name;
  const password = req.body.password;

  if (email && name && password) {
    User.findOne({
      email: {
        $regex: email,
      },
    }).then((user) => {
      if (user) {
        console.log('Email already exists');
        res.render('login', {
          message: 'Email already exists',
        });
      } else {
        new User({
          name: name,
          email: email,
          password: password,
        }).save((err) => {
          if (err) throw err;
          res.cookie(
            'ssonode',
            {
              status: true,
              data: {
                user: user,
                token: token,
              },
            },
            {
              maxAge: 180 * 60 * 1000,
            }
          );
          res.json({
            status: true,
            data: {
              user: user,
              token: token,
            },
          });
          console.log('New user registered Successfully');
        });
      }
    });
  } else {
    console.log('Error');
    // alert('Please Fill All Fields');
    res.json({
      status: false,
    });
  }
};

exports.logout = (req, res) => {
  req.logout();
  req.flash('success', 'You are now logged out! 👍');
  res.redirect('/');
};