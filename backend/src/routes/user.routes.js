const express = require('express');
const { authenticateUser } = require('../middleware/auth.middleware');
const { getProfile } = require('../controllers/user.controller');

const router = express.Router();

router.get('/profile', authenticateUser, getProfile);

module.exports = router;
