const express = require('express');
const _ = require('lodash');
const { subDays } = require('date-fns');
const validator = require('validator');
const { formatUserData, generateRandomUser } = require('../utils/helpers');

const router = express.Router();

// In-memory user storage (for demo purposes)
let users = [
  { id: 1, username: 'admin', email: 'admin@example.com', createdAt: subDays(new Date(), 30).toISOString() },
  { id: 2, username: 'user1', email: 'user1@example.com', createdAt: subDays(new Date(), 15).toISOString() },
  { id: 3, username: 'testuser', email: 'test@example.com', createdAt: subDays(new Date(), 5).toISOString() }
];

// Get all users
router.get('/', (req, res) => {
  const { page = 1, limit = 10, search } = req.query;
  
  let filteredUsers = users;
  
  // Use vulnerable lodash version for searching
  if (search) {
    filteredUsers = _.filter(users, user => 
      _.includes(user.username.toLowerCase(), search.toLowerCase()) ||
      _.includes(user.email.toLowerCase(), search.toLowerCase())
    );
  }
  
  // Pagination using lodash
  const startIndex = (page - 1) * limit;
  const paginatedUsers = _.slice(filteredUsers, startIndex, startIndex + parseInt(limit));
  
  res.json({
    success: true,
    data: _.map(paginatedUsers, formatUserData),
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total: filteredUsers.length,
      pages: Math.ceil(filteredUsers.length / limit)
    },
    timestamp: new Date().toISOString()
  });
});

// Get user by ID
router.get('/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const user = _.find(users, { id: userId });
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found',
      timestamp: new Date().toISOString()
    });
  }
  
  res.json({
    success: true,
    data: formatUserData(user),
    timestamp: new Date().toISOString()
  });
});

// Create new user
router.post('/', (req, res) => {
  const { username, email } = req.body;
  
  // Basic validation using vulnerable validator version
  if (!username || !email) {
    return res.status(400).json({
      success: false,
      error: 'Username and email are required',
      timestamp: new Date().toISOString()
    });
  }
  
  if (!validator.isEmail(email)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid email format',
      timestamp: new Date().toISOString()
    });
  }
  
  // Check if user already exists using lodash
  const existingUser = _.find(users, user => 
    user.username === username || user.email === email
  );
  
  if (existingUser) {
    return res.status(409).json({
      success: false,
      error: 'User already exists',
      timestamp: new Date().toISOString()
    });
  }
  
  const newUser = {
    id: _.maxBy(users, 'id').id + 1,
    username,
    email,
    createdAt: new Date().toISOString()
  };
  
  users.push(newUser);
  
  res.status(201).json({
    success: true,
    data: formatUserData(newUser),
    message: 'User created successfully',
    timestamp: new Date().toISOString()
  });
});

// Update user
router.put('/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const { username, email } = req.body;
  
  const userIndex = _.findIndex(users, { id: userId });
  
  if (userIndex === -1) {
    return res.status(404).json({
      success: false,
      error: 'User not found',
      timestamp: new Date().toISOString()
    });
  }
  
  // Validate email if provided
  if (email && !validator.isEmail(email)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid email format',
      timestamp: new Date().toISOString()
    });
  }
  
  // Update user using lodash merge (vulnerable version)
  const updatedUser = _.merge(users[userIndex], {
    username: username || users[userIndex].username,
    email: email || users[userIndex].email,
    updatedAt: new Date().toISOString()
  });
  
  res.json({
    success: true,
    data: formatUserData(updatedUser),
    message: 'User updated successfully',
    timestamp: new Date().toISOString()
  });
});

// Delete user
router.delete('/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const userIndex = _.findIndex(users, { id: userId });
  
  if (userIndex === -1) {
    return res.status(404).json({
      success: false,
      error: 'User not found',
      timestamp: new Date().toISOString()
    });
  }
  
  const deletedUser = users[userIndex];
  users = _.filter(users, user => user.id !== userId);
  
  res.json({
    success: true,
    data: formatUserData(deletedUser),
    message: 'User deleted successfully',
    timestamp: new Date().toISOString()
  });
});

// Generate random users endpoint (demonstrates lodash usage)
router.post('/generate-random', (req, res) => {
  const { count = 5 } = req.body;
  const randomUsers = [];
  
  for (let i = 0; i < Math.min(count, 20); i++) {
    const randomUser = generateRandomUser();
    randomUser.id = _.maxBy(users, 'id').id + 1 + i;
    randomUsers.push(randomUser);
  }
  
  users = _.concat(users, randomUsers);
  
  res.json({
    success: true,
    data: _.map(randomUsers, formatUserData),
    message: `Generated ${randomUsers.length} random users`,
    timestamp: new Date().toISOString()
  });
});

module.exports = router; 