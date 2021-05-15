const express = require('express');
const router = express.Router();

const authController = require("../controllers/AuthController");

router.get('/verifytoken', authController.getLogin);

module.exports = router;