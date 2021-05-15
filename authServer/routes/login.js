const express = require('express');
const router = express.Router();

const authController = require("../controllers/AuthController");

router.get('/', authController.getLogin);
router.post('/', authController.login);

module.exports = router;