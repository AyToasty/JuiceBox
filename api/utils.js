const jwt = require('jsonwebtoken');
const { getUserById } = require('../db');

async function requireUser(req, res, next) {
  try {
    const token = req.header('Authorization').split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authentication failed: Missing token' });
    }

    const { id } = jwt.verify(token, process.env.JWT_SECRET);
    if (!id) {
      return res.status(401).json({ message: 'Authentication failed: Invalid token' });
    }

    const user = await getUserById(id);
    if (!user) {
      return res.status(401).json({ message: 'Authentication failed: User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error(error);
    return res.status(401).json({ message: 'Authentication failed: Invalid token' });
  }
}
module.exports = {
  requireUser
}