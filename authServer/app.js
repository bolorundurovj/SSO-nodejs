const express = require('express');
const app = express();
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const hbs = require('express-handlebars');
const config = require('./config');
const { port, secret, database } = require('./config');

mongoose.connect(database.url);
mongoose.connection.on('error', (err) => {
  console.error(`🙅 🚫 🙅 🚫 🙅 🚫 🙅 🚫 → ${err.message}`);
});
const loginRouter = require('./routes/login');
const registerRouter = require('./routes/register');
const authRouter = require('./routes/index');


app.use(
  session({
    secret: secret,
    resave: false,
    saveUninitialized: true,
  })
);
app.use((req, res, next) => {
  console.log(req.session);
  next();
});
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.set('views', path.join(__dirname, 'views'));
app.engine('.hbs', hbs({extname: '.hbs'}));
app.set('view engine', '.hbs');

app.get('/', (req, res, next) => {
  const user = req.session.user || 'Unauthenticated';
  res.render('home', {
    user: `SSO-Server ${user}`,
    title: 'SSO-Server | Home',
  });
});
app.use('/login', loginRouter);
app.use('/register', registerRouter);
app.use('/auth', authRouter);

app.use((req, res, next) => {
  const err = new Error('Resource Not Found');
  err.status = 404;
  next(err);
});

app.use((err, req, res, next) => {
  console.error({
    message: err.message,
    error: err,
  });
  const statusCode = err.status || 500;
  let message = err.message || 'Internal Server Error';

  if (statusCode === 500) {
    message = 'Internal Server Error';
  }
  res.status(statusCode).json({ message });
});

const server = app.listen(config.port, () =>
  console.log(
    `SSO Server is running in ${
      process.env.NODE_ENV || 'development'
    } mode on port http://localhost:${config.port}`
  )
);

//Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
  console.log(`Error: ${err.message}`);
  //Close server && exit process
  server.close(() => {
    process.exit(1);
  });
});

module.exports = app;
