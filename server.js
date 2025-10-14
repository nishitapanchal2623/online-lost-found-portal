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

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});