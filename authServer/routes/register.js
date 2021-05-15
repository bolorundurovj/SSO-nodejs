const express = require('express');
const router = express.Router();

const authController = require("../controllers/AuthController");

router.get('/', function (req, res, next) {
  res.render('register', { title: 'Login' });
});
router.post('/', authController.register);

module.exports = router;
