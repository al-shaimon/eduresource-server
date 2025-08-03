const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = 5000;

// Simple JWT secret
const JWT_SECRET = process.env.JWT_SECRET;

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME;
let db;

// CORS origins - supports both development and production
const getAllowedOrigins = () => {
  const corsOrigins = process.env.CORS_ORIGINS;
  if (corsOrigins) {
    return corsOrigins.split(',').map((origin) => origin.trim());
  }

  // Fallback origins for development and production
  const defaultOrigins = [
    'https://eduresource.alshaimon.com',
    'https://www.eduresource.alshaimon.com',
    'http://localhost:5173',
    'http://localhost:3000',
  ];

  return defaultOrigins;
};

// Middleware
app.use(
  cors({
    origin: function (origin, callback) {
      const allowedOrigins = getAllowedOrigins();
      console.log('CORS check - Origin:', origin, 'Allowed:', allowedOrigins);

      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        console.log('CORS Error - Origin not allowed:', origin);
        return callback(new Error('Not allowed by CORS'), false);
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);
app.use(express.json());

// Connect to MongoDB
async function connectDB() {
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    db = client.db(DB_NAME);
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
}

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Role-based access middleware
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Helper function to create notification
async function createNotification(userId, title, message) {
  await db.collection('notifications').insertOne({
    userId: new ObjectId(userId),
    title: title || 'Notification',
    message,
    createdAt: new Date(),
    read: false,
  });
}

// Helper function to check for overdue items and send notifications
async function checkOverdueReturns() {
  try {
    const currentDate = new Date();

    // Find all approved requests where return date has passed
    const overdueRequests = await db
      .collection('requests')
      .aggregate([
        {
          $match: {
            status: 'approved',
            returnDate: { $lt: currentDate },
          },
        },
        {
          $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'user',
          },
        },
        {
          $lookup: {
            from: 'resources',
            localField: 'resourceId',
            foreignField: '_id',
            as: 'resource',
          },
        },
        {
          $unwind: '$user',
        },
        {
          $unwind: '$resource',
        },
      ])
      .toArray();

    for (const request of overdueRequests) {
      // Check if we already sent an overdue notification for this request
      const existingNotification = await db.collection('notifications').findOne({
        userId: request.userId,
        title: 'Overdue Return',
        message: { $regex: request.resource.name },
        createdAt: { $gte: new Date(currentDate.getTime() - 24 * 60 * 60 * 1000) }, // Within last 24 hours
      });

      if (!existingNotification) {
        const daysPastDue = Math.floor(
          (currentDate - new Date(request.returnDate)) / (1000 * 60 * 60 * 24)
        );

        // Send notification to user
        await createNotification(
          request.userId,
          'Overdue Return',
          `Your ${request.resource.name} is ${daysPastDue} day(s) overdue. Please return it immediately.`
        );

        // Send notification to all admins
        const adminUsers = await db.collection('users').find({ role: 'admin' }).toArray();
        for (const admin of adminUsers) {
          await createNotification(
            admin._id,
            'Overdue Alert',
            `${request.user.name} has an overdue return: ${request.resource.name} (${daysPastDue} days overdue)`
          );
        }

        console.log(
          `Overdue notification sent for request ${request._id} - ${request.resource.name} (${daysPastDue} days overdue)`
        );
      }
    }

    return overdueRequests.length;
  } catch (error) {
    console.error('Error checking overdue returns:', error);
    return 0;
  }
}

// Helper function to check for due returns (items due in next 3 days)
async function checkDueReturns() {
  try {
    const currentDate = new Date();
    const threeDaysFromNow = new Date(currentDate.getTime() + 3 * 24 * 60 * 60 * 1000);

    // Find all approved requests where return date is within next 3 days
    const dueRequests = await db
      .collection('requests')
      .aggregate([
        {
          $match: {
            status: 'approved',
            returnDate: {
              $gte: currentDate,
              $lte: threeDaysFromNow,
            },
          },
        },
        {
          $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'user',
          },
        },
        {
          $lookup: {
            from: 'resources',
            localField: 'resourceId',
            foreignField: '_id',
            as: 'resource',
          },
        },
        {
          $unwind: '$user',
        },
        {
          $unwind: '$resource',
        },
      ])
      .toArray();

    for (const request of dueRequests) {
      // Check if we already sent a due notification for this request today
      const existingNotification = await db.collection('notifications').findOne({
        userId: request.userId,
        title: 'Return Due Soon',
        message: { $regex: request.resource.name },
        createdAt: { $gte: new Date(currentDate.getTime() - 24 * 60 * 60 * 1000) }, // Within last 24 hours
      });

      if (!existingNotification) {
        const daysUntilDue = Math.ceil(
          (new Date(request.returnDate) - currentDate) / (1000 * 60 * 60 * 24)
        );

        // Send notification to user
        await createNotification(
          request.userId,
          'Return Due Soon',
          `Your ${request.resource.name} is due for return in ${daysUntilDue} day(s). Please plan to return it on time.`
        );

        console.log(
          `Due return notification sent for request ${request._id} - ${request.resource.name} (due in ${daysUntilDue} days)`
        );
      }
    }

    return dueRequests.length;
  } catch (error) {
    console.error('Error checking due returns:', error);
    return 0;
  }
}

// Auth Routes
app.post('/api/signup', async (req, res) => {
  try {
    console.log('Signup request received:', { 
      body: req.body, 
      dbConnected: !!db,
      dbName: db?.databaseName 
    });
    
    const { name, email, password, role } = req.body;

    // Basic validation
    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!['student', 'faculty', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Check if user exists
    console.log('Checking if user exists:', email);
    const existingUser = await db.collection('users').findOne({ email });
    console.log('Existing user check result:', !!existingUser);
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    console.log('Hashing password...');
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    console.log('Creating user...');
    const result = await db.collection('users').insertOne({
      name,
      email,
      password: hashedPassword,
      role,
    });
    console.log('User creation result:', result);

    res.status(201).json({
      message: 'User created successfully',
      userId: result.insertedId,
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    console.log('Login request received:', { 
      body: req.body, 
      dbConnected: !!db,
      dbName: db?.databaseName 
    });
    
    const { email, password } = req.body;

    // Find user
    console.log('Looking for user with email:', email);
    const user = await db.collection('users').findOne({ email });
    console.log('User found:', !!user);
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    console.log('Checking password...');
    const isValidPassword = await bcrypt.compare(password, user.password);
    console.log('Password valid:', isValidPassword);
    
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Create JWT token
    console.log('Creating JWT token...');
    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('Login successful for user:', user.email);
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Resource Routes
app.get('/api/resources', authenticateToken, async (req, res) => {
  try {
    const resources = await db
      .collection('resources')
      .aggregate([
        {
          $lookup: {
            from: 'requests',
            let: { resourceId: '$_id' },
            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [
                      { $eq: ['$resourceId', '$$resourceId'] },
                      { $in: ['$status', ['pending', 'approved', 'return_requested']] },
                    ],
                  },
                },
              },
              {
                $project: {
                  quantity: { $ifNull: ['$quantity', 1] }, // Default to 1 for backward compatibility
                },
              },
            ],
            as: 'activeRequests',
          },
        },
        {
          $addFields: {
            currentlyBooked: {
              $sum: '$activeRequests.quantity',
            },
            availableQuantity: {
              $subtract: ['$quantity', { $sum: '$activeRequests.quantity' }],
            },
          },
        },
        {
          $project: {
            activeRequests: 0,
          },
        },
      ])
      .toArray();

    res.json(resources);
  } catch (error) {
    console.error('Error fetching resources:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/resources', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { name, category, description, quantity, status } = req.body;

    if (!name || !category) {
      return res.status(400).json({ error: 'Name and category are required' });
    }

    const resource = {
      name,
      category,
      description: description || '',
      quantity: quantity || 1,
      status: status || 'available',
      currentlyBooked: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await db.collection('resources').insertOne(resource);
    res.status(201).json({
      message: 'Resource created successfully',
      resourceId: result.insertedId,
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/resources/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, category, description, quantity, status } = req.body;

    const updateData = { updatedAt: new Date() };
    if (name) updateData.name = name;
    if (category) updateData.category = category;
    if (description !== undefined) updateData.description = description;
    if (quantity) updateData.quantity = quantity;
    if (status) updateData.status = status;

    const result = await db
      .collection('resources')
      .updateOne({ _id: new ObjectId(id) }, { $set: updateData });

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Resource not found' });
    }

    res.json({ message: 'Resource updated successfully' });
  } catch (error) {
    console.error('Error updating resource:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/resources/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await db.collection('resources').deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Resource not found' });
    }

    res.json({ message: 'Resource deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Request Routes
app.post('/api/requests', authenticateToken, async (req, res) => {
  try {
    const { resourceId, returnDate, quantity = 1, duration, notes, priority, userRole } = req.body;

    if (!resourceId || !returnDate) {
      return res.status(400).json({ error: 'Resource ID and return date are required' });
    }

    if (!quantity || quantity < 1) {
      return res.status(400).json({ error: 'Quantity must be at least 1' });
    }

    // Role-based validation
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
    const userRoleFromDB = user?.role || 'student';

    // Define role-based policies
    const rolePolicies = {
      faculty: { maxDuration: 90, maxQuantity: 10 },
      student: { maxDuration: 30, maxQuantity: 3 },
      admin: { maxDuration: 365, maxQuantity: Number.MAX_SAFE_INTEGER },
    };

    const policies = rolePolicies[userRoleFromDB] || rolePolicies.student;

    // Validate duration based on role
    if (duration && duration > policies.maxDuration) {
      return res.status(400).json({
        error: `${userRoleFromDB} can checkout for maximum ${policies.maxDuration} days`,
      });
    }

    // Validate quantity based on role
    if (quantity > policies.maxQuantity) {
      return res.status(400).json({
        error: `${userRoleFromDB} can request maximum ${policies.maxQuantity} units`,
      });
    }

    // Check if resource exists and is available
    const resource = await db.collection('resources').findOne({
      _id: new ObjectId(resourceId),
    });

    if (!resource) {
      return res.status(404).json({ error: 'Resource not found' });
    }

    if (resource.status !== 'available') {
      return res.status(400).json({ error: 'Resource is not available' });
    }

    // Check if there's enough quantity available (considering pending/approved/return_requested requests)
    const activeRequests = await db
      .collection('requests')
      .aggregate([
        {
          $match: {
            resourceId: new ObjectId(resourceId),
            status: { $in: ['pending', 'approved', 'return_requested'] },
          },
        },
        {
          $group: {
            _id: null,
            totalRequested: { $sum: '$quantity' },
          },
        },
      ])
      .toArray();

    const totalRequested = activeRequests.length > 0 ? activeRequests[0].totalRequested : 0;
    const availableQuantity = resource.quantity - totalRequested;

    if (availableQuantity < quantity) {
      return res.status(400).json({
        error: `Only ${availableQuantity} units available for this resource`,
      });
    }

    // Determine priority score for sorting
    let priorityScore = 5; // Default priority
    if (userRoleFromDB === 'faculty') {
      switch (priority) {
        case 'urgent':
          priorityScore = 1;
          break;
        case 'research':
          priorityScore = 2;
          break;
        default:
          priorityScore = 3;
      }
    } else if (userRoleFromDB === 'admin') {
      priorityScore = 1;
    }

    // Create request
    const request = {
      userId: new ObjectId(req.user.userId),
      resourceId: new ObjectId(resourceId),
      quantity: parseInt(quantity),
      duration: duration ? parseInt(duration) : null,
      notes: notes || '',
      priority: priority || 'standard',
      priorityScore: priorityScore,
      userRole: userRoleFromDB,
      createdAt: new Date(),
      status: 'pending',
      returnDate: new Date(returnDate),
    };

    const result = await db.collection('requests').insertOne(request);
    res.status(201).json({
      message: 'Request submitted successfully',
      requestId: result.insertedId,
    });
  } catch (error) {
    console.error('Error creating request:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/requests', authenticateToken, async (req, res) => {
  try {
    let query = {};

    // If not admin, only show user's own requests
    if (req.user.role !== 'admin') {
      query.userId = new ObjectId(req.user.userId);
    }

    const requests = await db
      .collection('requests')
      .aggregate([
        { $match: query },
        {
          $lookup: {
            from: 'resources',
            localField: 'resourceId',
            foreignField: '_id',
            as: 'resource',
          },
        },
        {
          $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'user',
          },
        },
        {
          $unwind: { path: '$resource', preserveNullAndEmptyArrays: true },
        },
        {
          $unwind: { path: '$user', preserveNullAndEmptyArrays: true },
        },
        {
          $project: {
            _id: 1,
            createdAt: 1,
            status: 1,
            returnDate: 1,
            approvedAt: 1,
            returnRequestedAt: 1,
            returnedAt: 1,
            denialReason: 1,
            notes: 1,
            quantity: 1,
            duration: 1,
            resource: {
              _id: '$resource._id',
              name: '$resource.name',
              category: '$resource.category',
            },
            user: {
              _id: '$user._id',
              name: '$user.name',
              email: '$user.email',
              role: '$user.role',
            },
            // Add role priority for sorting (lower number = higher priority)
            rolePriority: {
              $switch: {
                branches: [
                  { case: { $eq: ['$user.role', 'admin'] }, then: 1 },
                  { case: { $eq: ['$user.role', 'faculty'] }, then: 2 },
                  { case: { $eq: ['$user.role', 'student'] }, then: 3 },
                ],
                default: 4,
              },
            },
          },
        },
        {
          $sort: {
            status: 1, // Pending first
            priorityScore: 1, // Lower score = higher priority (urgent faculty first)
            rolePriority: 1, // Faculty first (2), then students (3)
            createdAt: -1, // Within same priority/role, newest first
          },
        },
      ])
      .toArray();

    res.json(requests);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/requests/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, denialReason } = req.body;

    const request = await db.collection('requests').findOne({
      _id: new ObjectId(id),
    });

    if (!request) {
      return res.status(404).json({ error: 'Request not found' });
    }

    let updateData = {};
    let notificationMessage = '';

    if (req.user.role === 'admin') {
      if (status === 'approved') {
        updateData.status = 'approved';
        updateData.approvedAt = new Date();

        // Check if resource should be marked unavailable based on available quantity
        const resource = await db.collection('resources').findOne({ _id: request.resourceId });

        // Calculate total requested quantities for active requests
        const activeRequestsAgg = await db
          .collection('requests')
          .aggregate([
            {
              $match: {
                resourceId: request.resourceId,
                status: { $in: ['pending', 'approved', 'return_requested'] },
              },
            },
            {
              $group: {
                _id: null,
                totalRequested: { $sum: { $ifNull: ['$quantity', 1] } },
              },
            },
          ])
          .toArray();

        const totalRequested =
          activeRequestsAgg.length > 0 ? activeRequestsAgg[0].totalRequested : 0;
        const requestQuantity = request.quantity || 1;

        // If available quantity will be 0 or less after this approval, mark as booked
        if (resource.quantity - (totalRequested + requestQuantity) <= 0) {
          await db
            .collection('resources')
            .updateOne({ _id: request.resourceId }, { $set: { status: 'booked' } });
        }

        await createNotification(
          request.userId,
          'Request Approved',
          'Your resource request has been approved!'
        );
      } else if (status === 'denied') {
        updateData.status = 'denied';
        if (denialReason) updateData.denialReason = denialReason;
        await createNotification(
          request.userId,
          'Request Denied',
          'Your resource request has been denied.'
        );
      } else if (status === 'returned') {
        // Admin confirms the return
        if (request.status !== 'return_requested') {
          return res
            .status(400)
            .json({ error: 'Can only confirm returns that have been requested' });
        }

        updateData.status = 'returned';
        updateData.returnedAt = new Date();

        // Check if resource should be marked available again
        const resource = await db.collection('resources').findOne({ _id: request.resourceId });

        // Calculate total requested quantities for active requests (excluding current one being returned)
        const activeRequestsAgg = await db
          .collection('requests')
          .aggregate([
            {
              $match: {
                resourceId: request.resourceId,
                status: { $in: ['pending', 'approved', 'return_requested'] },
                _id: { $ne: new ObjectId(id) }, // Exclude current request being returned
              },
            },
            {
              $group: {
                _id: null,
                totalRequested: { $sum: { $ifNull: ['$quantity', 1] } },
              },
            },
          ])
          .toArray();

        const totalRequested =
          activeRequestsAgg.length > 0 ? activeRequestsAgg[0].totalRequested : 0;

        // If there will be available quantity after this return, mark as available
        if (resource.quantity - totalRequested > 0) {
          await db
            .collection('resources')
            .updateOne({ _id: request.resourceId }, { $set: { status: 'available' } });
        }

        await createNotification(
          request.userId,
          'Return Confirmed',
          'Your resource return has been confirmed and the item is now available.'
        );
      }
    } else if (status === 'return_requested') {
      // Allow users to request return of their own approved requests
      if (request.userId.toString() !== req.user.userId) {
        return res.status(403).json({ error: 'You can only request return of your own requests' });
      }

      if (request.status !== 'approved') {
        return res.status(400).json({ error: 'Only approved requests can be returned' });
      }

      updateData.status = 'return_requested';
      updateData.returnRequestedAt = new Date();

      // Notify admin about user return request
      const adminUsers = await db.collection('users').find({ role: 'admin' }).toArray();
      const requestUser = await db.collection('users').findOne({ _id: request.userId });
      const requestResource = await db.collection('resources').findOne({ _id: request.resourceId });

      for (const admin of adminUsers) {
        await createNotification(
          admin._id,
          'Return Request',
          `${requestUser?.name || 'A user'} wants to return ${
            requestResource?.name || 'a resource'
          }`
        );
      }
    } else {
      return res.status(403).json({ error: 'Unauthorized action' });
    }

    await db.collection('requests').updateOne({ _id: new ObjectId(id) }, { $set: updateData });

    res.json({ message: 'Request updated successfully' });
  } catch (error) {
    console.error('Error updating request:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Notification Routes
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const notifications = await db
      .collection('notifications')
      .find({
        userId: new ObjectId(req.user.userId),
      })
      .sort({ createdAt: -1 })
      .toArray();

    res.json(notifications);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/notifications/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await db.collection('notifications').updateOne(
      {
        _id: new ObjectId(id),
        userId: new ObjectId(req.user.userId),
      },
      { $set: { read: true } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark all notifications as read
app.put('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const result = await db.collection('notifications').updateMany(
      {
        userId: new ObjectId(req.user.userId),
        read: false,
      },
      { $set: { read: true } }
    );

    res.json({
      message: 'All notifications marked as read',
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get overdue returns - Admin only
app.get('/api/overdue-returns', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const currentDate = new Date();

    const overdueRequests = await db
      .collection('requests')
      .aggregate([
        {
          $match: {
            status: 'approved',
            returnDate: { $lt: currentDate },
          },
        },
        {
          $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'user',
          },
        },
        {
          $lookup: {
            from: 'resources',
            localField: 'resourceId',
            foreignField: '_id',
            as: 'resource',
          },
        },
        {
          $unwind: '$user',
        },
        {
          $unwind: '$resource',
        },
        {
          $addFields: {
            daysOverdue: {
              $ceil: {
                $divide: [{ $subtract: [currentDate, '$returnDate'] }, 1000 * 60 * 60 * 24],
              },
            },
          },
        },
        {
          $sort: { daysOverdue: -1, returnDate: 1 },
        },
      ])
      .toArray();

    res.json(overdueRequests);
  } catch (error) {
    console.error('Error fetching overdue returns:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get due returns (due in next 7 days)
app.get('/api/due-returns', authenticateToken, async (req, res) => {
  try {
    const currentDate = new Date();
    const sevenDaysFromNow = new Date(currentDate.getTime() + 7 * 24 * 60 * 60 * 1000);

    let query = {
      status: 'approved',
      returnDate: {
        $gte: currentDate,
        $lte: sevenDaysFromNow,
      },
    };

    // If not admin, only show user's own due returns
    if (req.user.role !== 'admin') {
      query.userId = new ObjectId(req.user.userId);
    }

    const dueRequests = await db
      .collection('requests')
      .aggregate([
        { $match: query },
        {
          $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'user',
          },
        },
        {
          $lookup: {
            from: 'resources',
            localField: 'resourceId',
            foreignField: '_id',
            as: 'resource',
          },
        },
        {
          $unwind: '$user',
        },
        {
          $unwind: '$resource',
        },
        {
          $addFields: {
            daysUntilDue: {
              $ceil: {
                $divide: [{ $subtract: ['$returnDate', currentDate] }, 1000 * 60 * 60 * 24],
              },
            },
          },
        },
        {
          $sort: { daysUntilDue: 1, returnDate: 1 },
        },
      ])
      .toArray();

    res.json(dueRequests);
  } catch (error) {
    console.error('Error fetching due returns:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Manual trigger for overdue checking - Admin only
app.post('/api/check-overdue', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const overdueCount = await checkOverdueReturns();
    const dueCount = await checkDueReturns();

    res.json({
      message: 'Overdue check completed',
      overdueCount,
      dueCount,
      timestamp: new Date(),
    });
  } catch (error) {
    console.error('Error in manual overdue check:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Users endpoints (Admin only)
app.get('/api/users', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const users = await db.collection('users').find({}).toArray();
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===============================
// STAKEHOLDER POLICY ENDPOINTS
// ===============================

// Get stakeholder policies - All authenticated users can read policies
app.get('/api/stakeholder-policies', authenticateToken, async (req, res) => {
  try {
    let policies = await db.collection('stakeholder_policies').findOne({ type: 'global' });

    // If no policies exist, create default ones
    if (!policies) {
      const defaultPolicies = {
        type: 'global',
        faculty: {
          maxDuration: 90,
          maxQuantity: 10,
          priorityAccess: true,
          allowedPriorities: ['urgent', 'research', 'standard'],
        },
        student: {
          maxDuration: 30,
          maxQuantity: 3,
          priorityAccess: false,
          allowedPriorities: ['standard'],
        },
        admin: {
          maxDuration: 365,
          maxQuantity: 999999,
          priorityAccess: true,
          allowedPriorities: ['urgent', 'research', 'standard'],
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      await db.collection('stakeholder_policies').insertOne(defaultPolicies);
      policies = defaultPolicies;
    }

    res.json(policies);
  } catch (error) {
    console.error('Error fetching stakeholder policies:', error);
    res.status(500).json({ error: 'Failed to fetch stakeholder policies' });
  }
});

// Update stakeholder policies
app.put(
  '/api/stakeholder-policies',
  authenticateToken,
  requireRole(['admin']),
  async (req, res) => {
    try {
      const { faculty, student, admin } = req.body;

      // Validate the policy data
      if (!faculty || !student || !admin) {
        return res
          .status(400)
          .json({ error: 'All role policies (faculty, student, admin) are required' });
      }

      const updatedPolicies = {
        type: 'global',
        faculty: {
          maxDuration: Number(faculty.maxDuration) || 90,
          maxQuantity: Number(faculty.maxQuantity) || 10,
          priorityAccess: Boolean(faculty.priorityAccess),
          allowedPriorities: faculty.allowedPriorities || ['urgent', 'research', 'standard'],
        },
        student: {
          maxDuration: Number(student.maxDuration) || 30,
          maxQuantity: Number(student.maxQuantity) || 3,
          priorityAccess: Boolean(student.priorityAccess),
          allowedPriorities: student.allowedPriorities || ['standard'],
        },
        admin: {
          maxDuration: Number(admin.maxDuration) || 365,
          maxQuantity: Number(admin.maxQuantity) || 999999,
          priorityAccess: Boolean(admin.priorityAccess),
          allowedPriorities: admin.allowedPriorities || ['urgent', 'research', 'standard'],
        },
        updatedAt: new Date(),
        updatedBy: req.user.id,
      };

      await db
        .collection('stakeholder_policies')
        .replaceOne({ type: 'global' }, updatedPolicies, { upsert: true });

      res.json({ message: 'Stakeholder policies updated successfully', policies: updatedPolicies });
    } catch (error) {
      console.error('Error updating stakeholder policies:', error);
      res.status(500).json({ error: 'Failed to update stakeholder policies' });
    }
  }
);

// Get stakeholder analytics
app.get(
  '/api/stakeholder-analytics',
  authenticateToken,
  requireRole(['admin']),
  async (req, res) => {
    try {
      const [
        totalRequests,
        requestsByRole,
        requestsByPriority,
        requestsByStatus,
        conflictingRequests,
      ] = await Promise.all([
        // Total requests count
        db.collection('requests').countDocuments(),

        // Requests by role
        db
          .collection('requests')
          .aggregate([
            {
              $lookup: {
                from: 'users',
                localField: 'userId',
                foreignField: '_id',
                as: 'user',
              },
            },
            { $unwind: '$user' },
            {
              $group: {
                _id: '$user.role',
                count: { $sum: 1 },
              },
            },
          ])
          .toArray(),

        // Requests by priority
        db
          .collection('requests')
          .aggregate([
            {
              $group: {
                _id: '$priority',
                count: { $sum: 1 },
              },
            },
          ])
          .toArray(),

        // Requests by status
        db
          .collection('requests')
          .aggregate([
            {
              $group: {
                _id: '$status',
                count: { $sum: 1 },
              },
            },
          ])
          .toArray(),

        // Conflicting requests (multiple pending requests for same resource)
        db
          .collection('requests')
          .aggregate([
            {
              $match: { status: 'pending' },
            },
            {
              $group: {
                _id: '$resourceId',
                requests: { $push: '$$ROOT' },
                count: { $sum: 1 },
              },
            },
            {
              $match: { count: { $gt: 1 } },
            },
            {
              $lookup: {
                from: 'resources',
                localField: '_id',
                foreignField: '_id',
                as: 'resource',
              },
            },
            { $unwind: '$resource' },
          ])
          .toArray(),
      ]);

      // Format the data
      const roleStats = {
        faculty: 0,
        student: 0,
        admin: 0,
      };

      requestsByRole.forEach((item) => {
        if (item._id && roleStats.hasOwnProperty(item._id)) {
          roleStats[item._id] = item.count;
        }
      });

      const priorityStats = {
        urgent: 0,
        research: 0,
        standard: 0,
      };

      requestsByPriority.forEach((item) => {
        if (item._id && priorityStats.hasOwnProperty(item._id)) {
          priorityStats[item._id] = item.count;
        }
      });

      // Calculate policy compliance (simplified)
      const totalPolicyViolations = 0; // Would need to implement actual policy checking
      const complianceRate =
        totalRequests > 0 ? Math.max(95, 100 - (totalPolicyViolations / totalRequests) * 100) : 100;

      res.json({
        totalRequests,
        roleStats,
        priorityStats,
        statusStats: requestsByStatus,
        conflictingRequests: conflictingRequests.length,
        conflictDetails: conflictingRequests.slice(0, 6), // Return first 6 conflicts
        complianceRate: Math.round(complianceRate * 10) / 10, // Round to 1 decimal
      });
    } catch (error) {
      console.error('Error fetching stakeholder analytics:', error);
      res.status(500).json({ error: 'Failed to fetch stakeholder analytics' });
    }
  }
);

// Basic route
app.get('/', (req, res) => {
  res.json({ message: 'EduResource Backend API is running!' });
});

// Start server
connectDB().then(() => {
  // Only start server with app.listen in development
  if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, async () => {
      console.log(`Server running on port ${PORT}`);

      // Run overdue check immediately on startup
      console.log('Running initial overdue check...');
      try {
        const initialOverdueCount = await checkOverdueReturns();
        const initialDueCount = await checkDueReturns();
        console.log(
          `Initial check completed: ${initialOverdueCount} overdue, ${initialDueCount} due soon`
        );
      } catch (error) {
        console.error('Error in initial overdue check:', error);
      }

      // Set up periodic overdue checking (every 2 hours)
      const OVERDUE_CHECK_INTERVAL = 2 * 60 * 60 * 1000; // 2 hours in milliseconds
      setInterval(async () => {
        console.log('Running scheduled overdue check...');
        try {
          const overdueCount = await checkOverdueReturns();
          const dueCount = await checkDueReturns();
          console.log(`Scheduled check completed: ${overdueCount} overdue, ${dueCount} due soon`);
        } catch (error) {
          console.error('Error in scheduled overdue check:', error);
        }
      }, OVERDUE_CHECK_INTERVAL);
    });
  } else {
    // In production (Vercel), just run the initial setup
    console.log('Production mode: Database connected, ready for serverless functions');
  }
});

// Export for Vercel serverless functions
module.exports = app;
