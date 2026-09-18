const { getAllUsers: fetchAllUsers } = require('../models/user.model');
const { logSecurityEvent } = require('../utils/logger');

const getAllUsers = async (req, res) => {
    try {
        const users = await fetchAllUsers();
        res.status(200).json(users);
    } catch (err) {
        console.error('Error fetching all users:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
};

module.exports = { getAllUsers };

