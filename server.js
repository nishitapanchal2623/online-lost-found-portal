const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Middleware - CORS FIX ADD KAR DIYA
app.use(cors({
  origin: "http://127.0.0.1:5500",
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ UPLOADS FOLDER CREATE IF NOT EXISTS
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('Uploads folder created successfully');
}
app.use('/uploads', express.static(uploadsDir));

// Database connection - PASSWORD CHANGE KARNA
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Meet1234@',
  database: 'lost_and_found'
});

// Connect to database
db.connect((err) => {
  if (err) {
    console.log('Database connection failed. Please check your MySQL installation and password.');
    console.log('Error: ', err.message);
    return;
  }
  console.log('Connected to MySQL database');
});

// Configure file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Signup endpoint - PHONE NUMBER ADD KIYA
app.post('/api/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  
  try {
    // Check if user already exists
    db.query('SELECT * FROM lostandfound WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.log('Database Error in signup:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (results.length > 0) {
        return res.status(400).json({ error: 'User already exists with this email' });
      }
      
      // Hash password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      
      // Insert user into database with PHONE NUMBER
      db.query(
        'INSERT INTO lostandfound (name, email, phone, password) VALUES (?, ?, ?, ?)',
        [name, email, phone, hashedPassword],
        (err, results) => {
          if (err) {
            console.log('Database Insert Error:', err);
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
          res.status(201).json({ 
            message: 'User created successfully',
            userId: results.insertId 
          });
        }
      );
    });
  } catch (error) {
    console.log('Signup Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  // Find user by email
  db.query('SELECT * FROM lostandfound WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.log('Database Error in login:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const user = results[0];
    
    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Don't send password back to client
    const userResponse = {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      profilePicture: user.profile_picture
    };
    
    res.json({ 
      message: 'Login successful', 
      user: userResponse 
    });
  });
});

// Upload profile picture
app.post('/api/upload-profile', upload.single('profilePicture'), (req, res) => {
  const userId = req.body.userId;
  
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const profilePicturePath = `uploads/${req.file.filename}`;
  
  console.log('File uploaded successfully:', req.file);
  
  // Update user profile picture in database
  db.query(
    'UPDATE lostandfound SET profile_picture = ? WHERE id = ?',
    [profilePicturePath, userId],
    (err, results) => {
      if (err) {
        console.log('Database Update Error:', err);
        return res.status(500).json({ error: 'Failed to update profile picture' });
      }
      
      res.json({ 
        message: 'Profile picture updated successfully',
        profilePicture: profilePicturePath 
      });
    }
  );
});

// Get user data
app.get('/api/user/:id', (req, res) => {
  const userId = req.params.id;
  
  db.query('SELECT id, name, email, phone, profile_picture FROM lostandfound WHERE id = ?', [userId], (err, results) => {
    if (err) {
      console.log('Database Error in get user:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user: results[0] });
  });
});

// ✅ NEW: Save report to DATABASE (NOT JSON FILE)
app.post('/api/save-report', upload.single('itemPhoto'), async (req, res) => {
  const reportData = req.body;
  const user = JSON.parse(reportData.userData);
  
  try {
    let photoPath = null;
    
    // If photo uploaded, save it
    if (req.file) {
      photoPath = `uploads/${req.file.filename}`;
    }
    
    // Insert report into MySQL database
    db.query(
      `INSERT INTO reports 
      (type, item_name, category, description, location, date, contact, reward, photo_path, user_id) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        reportData.type,
        reportData.itemName,
        reportData.category,
        reportData.description,
        reportData.location,
        reportData.date,
        reportData.contact,
        reportData.reward || null,
        photoPath,
        user.id
      ],
      (err, results) => {
        if (err) {
          console.log('Database Insert Error:', err);
          return res.status(500).json({ error: 'Failed to save report to database' });
        }
        
        res.json({ 
          message: 'Report saved successfully to database',
          reportId: results.insertId 
        });
      }
    );
  } catch (error) {
    console.error('Error saving report:', error);
    res.status(500).json({ error: 'Failed to save report' });
  }
});

// ✅ NEW: Get all reports from DATABASE
app.get('/api/reports', (req, res) => {
  db.query(
    `SELECT r.*, u.name as user_name, u.phone as user_phone, u.email as user_email 
     FROM reports r 
     JOIN lostandfound u ON r.user_id = u.id 
     ORDER BY r.created_at DESC`,
    (err, results) => {
      if (err) {
        console.log('Database Error in get reports:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      // Convert to same format as before for frontend compatibility
      const formattedReports = results.map(report => ({
        type: report.type,
        itemName: report.item_name,
        category: report.category,
        description: report.description,
        location: report.location,
        date: report.date,
        contact: report.contact,
        reward: report.reward,
        photo: report.photo_path ? `http://localhost:3000/${report.photo_path}` : null,
        userId: report.user_id,
        id: report.id.toString(),
        createdAt: report.created_at,
        userName: report.user_name,
        userPhone: report.user_phone,
        userEmail: report.user_email
      }));
      
      res.json({ reports: formattedReports });
    }
  );
});

// ✅ NEW: Get user's own reports
app.get('/api/user-reports/:userId', (req, res) => {
  const userId = req.params.userId;
  
  db.query(
    `SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC`,
    [userId],
    (err, results) => {
      if (err) {
        console.log('Database Error in get user reports:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      const formattedReports = results.map(report => ({
        type: report.type,
        itemName: report.item_name,
        category: report.category,
        description: report.description,
        location: report.location,
        date: report.date,
        contact: report.contact,
        reward: report.reward,
        photo: report.photo_path ? `http://localhost:3000/${report.photo_path}` : null,
        userId: report.user_id,
        id: report.id.toString(),
        createdAt: report.created_at
      }));
      
      res.json({ reports: formattedReports });
    }
  );
});

// ✅ NEW: Delete report from DATABASE
app.delete('/api/reports/:reportId', (req, res) => {
  const reportId = req.params.reportId;
  
  db.query('DELETE FROM reports WHERE id = ?', [reportId], (err, results) => {
    if (err) {
      console.log('Database Error in delete report:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ message: 'Report deleted successfully' });
  });
});

// ✅ ADMIN: Admin Login - WORKING FIX
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  console.log('Admin login attempt:', username, password);
  
  // Simple admin authentication - HARDCODED
  if (username === 'admin' && password === 'admin123') {
    console.log('Admin login SUCCESS');
    res.json({ 
      message: 'Admin login successful',
      admin: { username: 'admin', role: 'admin' }
    });
  } else {
    console.log('Admin login FAILED');
    res.status(401).json({ error: 'Invalid admin credentials' });
  }
});

// ✅ ADMIN: Get all reports (sab users ke)
app.get('/api/admin/reports', (req, res) => {
  db.query(
    `SELECT r.*, u.name as user_name, u.phone as user_phone, u.email as user_email 
     FROM reports r 
     JOIN lostandfound u ON r.user_id = u.id 
     ORDER BY r.created_at DESC`,
    (err, results) => {
      if (err) {
        console.log('Admin Database Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      const formattedReports = results.map(report => ({
        type: report.type,
        itemName: report.item_name,
        category: report.category,
        description: report.description,
        location: report.location,
        date: report.date,
        contact: report.contact,
        reward: report.reward,
        photo: report.photo_path ? `http://localhost:3000/${report.photo_path}` : null,
        userId: report.user_id,
        id: report.id.toString(),
        createdAt: report.created_at,
        userName: report.user_name,
        userPhone: report.user_phone,
        userEmail: report.user_email
      }));
      
      res.json({ reports: formattedReports });
    }
  );
});

// ✅ ADMIN: Delete any report (kisi ka bhi)
app.delete('/api/admin/reports/:reportId', (req, res) => {
  const reportId = req.params.reportId;
  
  db.query('DELETE FROM reports WHERE id = ?', [reportId], (err, results) => {
    if (err) {
      console.log('Admin Delete Error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ message: 'Report deleted successfully by admin' });
  });
});

// ✅ ADMIN: Get all users
app.get('/api/admin/users', (req, res) => {
  db.query(
    'SELECT id, name, email, phone, profile_picture, created_at FROM lostandfound ORDER BY created_at DESC',
    (err, results) => {
      if (err) {
        console.log('Admin Users Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({ users: results });
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});