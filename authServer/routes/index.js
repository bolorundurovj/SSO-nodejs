const express = require('express');
const router = express.Router();

const authController = require("../controllers/AuthController");

router.get('/verifytoken', authController.verifySSOToken);

module.exports = router;