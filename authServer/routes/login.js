const express = require('express');
const router = express.Router();

const authController = require("../controllers/AuthController");

router.get('/', authController.getLoginPage);
router.post('/', authController.loginUser);

module.exports = router;