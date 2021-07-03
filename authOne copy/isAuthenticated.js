const isAuthenticated = (req, res, next) => {
  // simple check to see if the user is authenicated or not,
  // if not redirect the user to the SSO Server for Login
  // pass the redirect URL as current URL
  // serviceURL is where the sso should redirect in case of valid user
  const redirectURL = `${req.protocol}://${req.headers.host}${req.path}`;
  console.log(req.session);
  if (req.session.user == null) {
    return res.redirect(
      `http://localhost:3000/sso/v1/login?serviceUrl=${redirectURL}`
      // `http://localhost:3010/login?serviceURL=${redirectURL}`
    );
  }
  next();
};

module.exports = isAuthenticated;
