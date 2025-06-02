const express = require('express');
const router = express.Router();
const { getUsers, getLeads } = require('../controllers/userController');

router.get('/users', getUsers);
router.get('/leads', getLeads);

module.exports = router;
