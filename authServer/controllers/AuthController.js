const User = require('../models/User');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const promisify = require('es6-promisify');
const jwt = require('jsonwebtoken');
const md5 = require('md5');
const { genJwtToken } = require("./jwt_helper");

const re = /(\S+)\s+(\S+)/;

// Note: Express http converts all headers to lower case.
const AUTH_HEADER = 'authorization';
const BEARER_AUTH_SCHEME = 'bearer';

function parseAuthHeader(header) {
  if (typeof header !== 'string') {
    return null;
  }
  const matches = header.match(re);
  return matches && {
    scheme: matches[1],
    value: matches[2]
  };
}

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

const fromAuthHeaderAsBearerToken = function () {
  return fromAuthHeaderWithScheme(BEARER_AUTH_SCHEME);
};

const appTokenFromRequest = tokenFromAuthHeader(BEARER_AUTH_SCHEME);

// The tokens are for validation
const intrmTokenCache = {};

const fillIntrmTokenCache = (origin, id, intrmToken) => {
  intrmTokenCache[intrmToken] = [id, originAppName[origin]];
};
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
  console.log({
    ...sessionApp
  }, {
    ...sessionUser
  }, {
    intrmTokenCache
  });
};

const generatePayload = (ssoToken) => {
  const globalSessionToken = intrmTokenCache[ssoToken][0];
  const appName = intrmTokenCache[ssoToken][1];
  const userEmail = sessionUser[globalSessionToken];
  const user = userDB[userEmail];
  const appPolicy = user.appPolicy[appName];
  const email = appPolicy.shareEmail === true ? userEmail : undefined;
  const payload = {
    ...{
      ...appPolicy
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
  const {
    ssoToken
  } = req.query;
  // if the application token is not present or ssoToken request is invalid
  // if the ssoToken is not present in the cache some is
  // smart.
  if (
    appToken == null ||
    ssoToken == null ||
    intrmTokenCache[ssoToken] == null
  ) {
    return res.status(400).json({
      message: 'badRequest'
    });
  }

  // if the appToken is present and check if it's valid for the application
  const appName = intrmTokenCache[ssoToken][1];
  const globalSessionToken = intrmTokenCache[ssoToken][0];
  // If the appToken is not equal to token given during the sso app registraion or later stage than invalid
  if (
    appToken !== appTokenDB[appName] ||
    sessionApp[globalSessionToken][appName] !== true
  ) {
    return res.status(403).json({
      message: 'Unauthorized'
    });
  }
  // checking if the token passed has been generated
  const payload = generatePayload(ssoToken);

  const token = await genJwtToken(payload);
  // delete the itremCache key for no futher use,
  delete intrmTokenCache[ssoToken];
  return res.status(200).json({
    token
  });
};

const sessionUser = {};
const sessionApp = {};

exports.getLogin = (req, res, next) => {
  const {
    serviceURL
  } = req.query;
  if (serviceURL != null) {
    const url = new URL(serviceURL);
    if (alloweOrigin[url.origin] !== true) {
      return res
        .status(400)
        .json({
          message: 'Your are not allowed to access the sso-server'
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

exports.login = (req, res, next) => {
  const {
    serviceURL
  } = req.query;
  const {
    email,
    password
  } = req.body;
  console.log('Logging in .....');

  User.findOne({
    email: email
  }).then((user) => {
    if (user) {
      bcrypt.compare(password, user.password, function (err, isMatch) {
        if (!isMatch) {
          console.log('Auth Error');
          res.render('login', {
            message: 'Auth Error'
          });
        }
        if (isMatch) {
          jwt.sign({
              email: email
            },
            'secretkey', {
              expiresIn: '10h'
            },
            (err, token) => {
              res.cookie(
                'ssonode', {
                  status: true,
                  data: {
                    user: user,
                    token: token,
                  },
                }, {
                  maxAge: 180 * 60 * 1000
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
      console.log('user does not exist');
      res.render('login', {
        message: 'Auth Error'
      });
    }
  });
};

exports.register = (req, res, next) => {
  const {
    serviceURL
  } = req.query;
  console.log('Registering ...', req.body);
  const email = req.body.email;
  const name = req.body.name;
  const password = req.body.password;

  if (email && name && password) {
    User.findOne({
      email: {
        $regex: email
      }
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
            'ssonode', {
              status: true,
              data: {
                user: user,
                token: token,
              },
            }, {
              maxAge: 180 * 60 * 1000
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
      status: false
    });
  }
};

exports.logout = (req, res) => {
  req.logout();
  req.flash('success', 'You are now logged out! 👍');
  res.redirect('/');
};

exports.isLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) {
    next();
    return;
  }
  req.flash('error', 'Oops! you must be logged in to do that!');
  res.redirect('/login');
};

exports.forgot = async (req, res) => {
  const user = await User.findOne({
    email: req.body.email
  });

  if (!user) {
    req.flash('error', 'No user with that email exists!');
    return res.redirect('/login');
  }

  user.resetPasswordToken = crypto.randomBytes(20).toString('hex');
  user.resetPasswordExpires = Date.now() + 3600000; //1hour in miliseconds
  await user.save();

  const resetURL = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`;

  // await mail.send({
  //   user,
  //   subject: 'Password Reset',
  //   resetURL,
  //   filename: 'password-reset'
  // });

  req.flash('success', `You have been emailed a password reset link.`);

  res.redirect('/login');
};

exports.reset = async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: {
      $gt: Date.now()
    },
  });
  if (!user) {
    req.flash('error', 'Password reset token is invalid or has expired');
    res.redirect('/login');
  }

  res.render('reset', {
    title: 'Reset Your Password'
  });
};

exports.confirmedPasswords = (req, res, next) => {
  if (req.body.password === req.body['password-confirm']) {
    next(); //move to next middleware
    return;
  }

  req.flash('error', 'Passwords do not match!');
  res.redirect('back');
};

exports.update = async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: {
      $gt: Date.now()
    },
  });
  if (!user) {
    req.flash('error', 'Password reset token is invalid or has expired');
    res.redirect('/login');
  }

  const setPassword = promisify(user.setPassword, user);
  await setPassword(req.body.password);
  user.resetPasswordExpires = undefined;
  user.resetPasswordToken = undefined;
  const updatedUser = await user.save();
  await req.login(updatedUser);
  req.flash(
    'success',
    ' 💃🏿 Your password has been reset!  You are now logged in'
  );
  res.redirect('/');
};