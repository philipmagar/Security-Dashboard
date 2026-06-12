const { users } = require('../models/user.model');

const getAllUsers = (req, res) => {
    const usersWithoutPasswords = users.map(({ password, ...u }) => u);
    res.status(200).json(usersWithoutPasswords);
};

module.exports = { getAllUsers };
