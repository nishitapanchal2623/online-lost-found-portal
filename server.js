const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
require('dotenv').config(); // Load environment variables

// ✅ Security middleware
const helmet = require('helmet'); // Add this after installing: npm install helmet

// ✅ Rate limiting middleware
const rateLimit = (windowMs, maxRequests) => {
  const clients = new Map();
  
  return (req, res, next) => {
    const clientId = req.ip;
    const now = Date.now();
    const clientData = clients.get(clientId) || { requests: 0, resetTime: now + windowMs };
    
    if (now > clientData.resetTime) {
      clientData.requests = 0;
      clientData.resetTime = now + windowMs;
    }
    
    if (clientData.requests >= maxRequests) {
      return res.status(429).json({ 
        error: 'Too many requests, please try again later.' 
      });
    }
    
    clientData.requests++;
    clients.set(clientId, clientData);
    next();
  };
};

const app = express();
const PORT = 3000;

// Helper to build a safe, encoded full URL for a stored relative path
function toUrl(relativePath) {
  if (!relativePath) return null;
  // Normalize separators and encode each path segment to handle spaces/special chars
  const clean = relativePath.replace(/\\/g, '/').split('/').map(encodeURIComponent).join('/');
  return `http://localhost:${PORT}/${clean}`;
}

// Middleware - CORS FIX ADD KAR DIYA
// Configure helmet but allow cross-origin resource loading for static assets (uploads)
// Some browsers block resources when Cross-Origin-Resource-Policy is set to 'same-origin'.
// Setting this to 'cross-origin' lets images served from this server be loaded
// by pages served from other origins (or file:// during local testing).
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
})); // Security headers with adjusted CORP
app.use(cors({
  origin: true, // Allow all origins
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ UPLOADS FOLDER CREATE IF NOT EXISTS
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('Uploads folder created successfully');
}
// Serve uploads but ensure the Cross-Origin-Resource-Policy allows images to be loaded
// by the frontend. We set the header on this route specifically so the rest of the
// app can keep stricter defaults if desired.
app.use('/uploads', (req, res, next) => {
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
}, express.static(uploadsDir));

// Debug endpoint to list files in uploads (safe, read-only). Returns JSON array of
// filename and fully-qualified URL so you can quickly verify uploaded files.
app.get('/api/uploads', (req, res) => {
  fs.readdir(uploadsDir, (err, files) => {
    if (err) {
      console.error('Failed to read uploads directory:', err.message);
      return res.status(500).json({ error: 'Failed to read uploads directory' });
    }

    const visibleFiles = (files || []).filter(f => !f.startsWith('.'));
    const payload = visibleFiles.map(f => ({
      file: f,
      url: `http://localhost:${PORT}/uploads/${encodeURIComponent(f)}`
    }));

    res.json({ files: payload });
  });
});

// ✅ SERVE FRONTEND STATIC FILES
const frontendDir = path.join(__dirname, '../frontend');
app.use(express.static(frontendDir));

// ✅ SERVE INDEX.HTML FOR ROOT PATH
app.get('/', (req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

// Database connection - PASSWORD CHANGE KARNA
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'Meet1234@',
  database: process.env.DB_NAME || 'lost_and_found'
});

// Connect to database
db.connect((err) => {
  if (err) {
    console.log('Database connection failed. Please check your MySQL installation and password.');
    console.log('Error: ', err.message);
    return;
  }
  console.log('Connected to MySQL database');
  initializeDatabase();
});

const initializeDatabase = () => {
  const createClaimsTable = `
    CREATE TABLE IF NOT EXISTS claims (
      id INT AUTO_INCREMENT PRIMARY KEY,
      report_id INT NOT NULL,
      claimer_id INT NOT NULL,
      message TEXT NOT NULL,
      status ENUM('pending','approved','rejected') DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `;

  const createNotificationsTable = `
    CREATE TABLE IF NOT EXISTS notifications (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      title VARCHAR(255) NOT NULL,
      body TEXT NOT NULL,
      link VARCHAR(255),
      is_read TINYINT(1) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  const createSupportChatsTable = `
    CREATE TABLE IF NOT EXISTS support_chats (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      message TEXT NOT NULL,
      sender_type ENUM('user','admin') NOT NULL,
      is_read TINYINT(1) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES lostandfound(id) ON DELETE CASCADE
    )
  `;

  // Create tables in sequence
  db.query(createClaimsTable, (err) => {
    if (err) {
      console.error('Failed to ensure claims table exists:', err.message);
    } else {
      console.log('✅ Claims table ready');
    }
  });

  db.query(createNotificationsTable, (err) => {
    if (err) {
      console.error('Failed to ensure notifications table exists:', err.message);
    } else {
      console.log('✅ Notifications table ready');
    }
  });

  db.query(createSupportChatsTable, (err) => {
    if (err) {
      console.error('Failed to ensure support_chats table exists:', err.message);
    } else {
      console.log('✅ Support chat system ready');
    }
  });

  // ✅ Create spam_reports table
  const createSpamReportsTable = `
    CREATE TABLE IF NOT EXISTS spam_reports (
      id INT AUTO_INCREMENT PRIMARY KEY,
      report_id INT NOT NULL,
      reporter_id INT NOT NULL,
      reason TEXT NOT NULL,
      status ENUM('pending','reviewed','dismissed') DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  db.query(createSpamReportsTable, (err) => {
    if (err) {
      console.error('Failed to ensure spam_reports table exists:', err.message);
    } else {
      console.log('✅ Spam reports table ready');
    }
  });

  db.query('SHOW COLUMNS FROM reports LIKE "status"', (err, results) => {
    if (!err && results.length === 0) {
      const addStatusColumn = `
        ALTER TABLE reports 
        ADD COLUMN status ENUM('open','pending_claim','matched','closed') DEFAULT 'open' AFTER reward
      `;
      db.query(addStatusColumn, (alterErr) => {
        if (alterErr) {
          console.error('Failed to add status column to reports table:', alterErr.message);
        } else {
          console.log('✅ Reports status column added');
        }
      });
    }
  });
};

const notifyUser = (userId, title, body, link = null) => {
  if (!userId) return;
  db.query(
    'INSERT INTO notifications (user_id, title, body, link) VALUES (?, ?, ?, ?)',
    [userId, title, body, link],
    (err) => {
      if (err) {
        console.error('Notification insert error:', err.message);
      }
    }
  );
};

const updateReportStatus = (reportId, status) => {
  if (!reportId || !status) return;
  db.query('UPDATE reports SET status = ? WHERE id = ?', [status, reportId], (err) => {
    if (err) {
      console.error('Failed to update report status:', err.message);
    }
  });
};

const findPotentialMatches = (report, callback) => {
  if (!report || !report.category || !report.location || !report.date) {
    return callback([]);
  }

  const query = `
    SELECT r.*, u.name as user_name, u.phone as user_phone, u.email as user_email
    FROM reports r
    JOIN lostandfound u ON r.user_id = u.id
    WHERE r.id != ?
      AND r.user_id != ?
      AND r.type != ?
      AND r.category = ?
      AND (r.location LIKE ? OR ? LIKE CONCAT('%', r.location, '%'))
      AND r.date IS NOT NULL
      AND ABS(TIMESTAMPDIFF(DAY, r.date, ?)) <= 30
    ORDER BY ABS(TIMESTAMPDIFF(DAY, r.date, ?)) ASC
    LIMIT 5
  `;

  const params = [
    report.id || 0,
    report.userId,
    report.type,
    report.category,
    `%${report.location}%`,
    report.location,
    report.date,
    report.date
  ];

  db.query(query, params, (err, results) => {
    if (err) {
      console.error('Match query error:', err.message);
      return callback([]);
    }
    callback(results || []);
  });
};

// Configure file uploads
// ✅ Always save files into the same physical folder that we are serving with express.static
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Use the absolute uploadsDir so it does NOT depend on where Node is started from
    cb(null, uploadsDir);
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
app.post('/api/signup', rateLimit(15 * 60 * 1000, 5), async (req, res) => {
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
app.post('/api/login', rateLimit(15 * 60 * 1000, 10), (req, res) => {
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
      profilePicture: toUrl(user.profile_picture)
    };
    
    res.json({ 
      message: 'Login successful', 
      user: userResponse 
    });
  });
});

// ✅ FORGOT PASSWORD - Generate reset code
const resetCodes = new Map(); // Store reset codes temporarily

// ✅ EMAIL SETUP
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

app.post('/api/forgot-password', rateLimit(15 * 60 * 1000, 5), (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  db.query('SELECT * FROM lostandfound WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error('Forgot password error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'No account found with this email' });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store code with 10-minute expiry
    resetCodes.set(email, {
      code,
      expiry: Date.now() + 10 * 60 * 1000 // 10 minutes
    });

    // ✅ SEND EMAIL WITH CODE
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Code - Lost and Found Portal',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #4361ee;">Password Reset Request</h2>
          <p>Hello,</p>
          <p>You requested a password reset for your Lost and Found Portal account.</p>
          <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
            <h3 style="margin: 0; color: #343a40;">Your Reset Code:</h3>
            <div style="font-size: 32px; font-weight: bold; color: #4361ee; letter-spacing: 5px; margin: 15px 0;">${code}</div>
            <p style="color: #6c757d; margin: 0;">This code expires in 10 minutes</p>
          </div>
          <p>If you didn't request this, please ignore this email.</p>
          <hr style="margin: 30px 0;">
          <p style="color: #6c757d; font-size: 12px;">Lost and Found Portal Team</p>
        </div>
      `
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Email error:', error);
        return res.status(500).json({ error: 'Failed to send email. Please try again.' });
      }
      
      console.log('Email sent: ' + info.response);
      res.json({ message: 'Reset code sent to your email' });
    });
  });
});

// ✅ RESET PASSWORD - Verify code and update password
app.post('/api/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  
  if (!email || !code || !newPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const storedData = resetCodes.get(email);

  if (!storedData) {
    return res.status(400).json({ error: 'No reset code found. Please request a new one.' });
  }

  if (Date.now() > storedData.expiry) {
    resetCodes.delete(email);
    return res.status(400).json({ error: 'Reset code expired. Please request a new one.' });
  }

  if (storedData.code !== code) {
    return res.status(400).json({ error: 'Invalid reset code' });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    db.query('UPDATE lostandfound SET password = ? WHERE email = ?', [hashedPassword, email], (err) => {
      if (err) {
        console.error('Password update error:', err);
        return res.status(500).json({ error: 'Failed to update password' });
      }

      resetCodes.delete(email);
      res.json({ message: 'Password reset successful' });
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ✅ REPORT SPAM/FRAUDULENT LISTING
app.post('/api/report-spam', (req, res) => {
  const { reportId, reporterId, reason } = req.body;
  
  if (!reportId || !reporterId || !reason) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Check if already reported by same user
  db.query(
    'SELECT * FROM spam_reports WHERE report_id = ? AND reporter_id = ?',
    [reportId, reporterId],
    (err, results) => {
      if (err) {
        console.error('Spam report check error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (results.length > 0) {
        return res.status(400).json({ error: 'You have already reported this item' });
      }

      // Insert spam report
      db.query(
        'INSERT INTO spam_reports (report_id, reporter_id, reason) VALUES (?, ?, ?)',
        [reportId, reporterId, reason],
        (insertErr) => {
          if (insertErr) {
            console.error('Spam report insert error:', insertErr);
            return res.status(500).json({ error: 'Failed to submit report' });
          }

          // Notify admin (in real app, send email)
          console.log(`Spam report submitted for report ${reportId}: ${reason}`);
          res.json({ message: 'Report submitted successfully' });
        }
      );
    }
  );
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
        profilePicture: toUrl(profilePicturePath)
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
    
    // Add full URL to profile picture
    const user = results[0];
    if (user.profile_picture) {
      user.profile_picture = toUrl(user.profile_picture);
    }
    
    res.json({ user });
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
        
        const newReport = {
          id: results.insertId,
          type: reportData.type,
          category: reportData.category,
          location: reportData.location,
          date: reportData.date,
          userId: user.id
        };

        findPotentialMatches(newReport, (matches) => {
          const formattedMatches = matches.map(match => ({
            id: match.id,
            itemName: match.item_name,
            type: match.type,
            category: match.category,
            location: match.location,
            date: match.date,
            contact: match.contact,
            reward: match.reward,
            photo: match.photo_path ? toUrl(match.photo_path) : null,
            userId: match.user_id,
            userName: match.user_name,
            userPhone: match.user_phone,
            userEmail: match.user_email
          }));

          if (formattedMatches.length > 0) {
            formattedMatches.forEach(match => {
              notifyUser(
                user.id,
                'Potential match found',
                `We found a ${match.type} report that looks similar to "${match.itemName}".`,
                null
              );

              notifyUser(
                match.userId,
                'Potential match found',
                `Your report "${match.itemName}" might match a new ${reportData.type} report.`,
                null
              );
            });
          }

          res.json({ 
            message: 'Report saved successfully to database',
            reportId: results.insertId,
            matches: formattedMatches
          });
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
  const { type, category, q, location, fromDate, toDate, userId } = req.query;
  const conditions = [];
  const params = [];

  if (type) {
    conditions.push('r.type = ?');
    params.push(type);
  }

  if (category) {
    conditions.push('r.category = ?');
    params.push(category);
  }

  if (location) {
    conditions.push('r.location LIKE ?');
    params.push(`%${location}%`);
  }

  if (userId) {
    conditions.push('r.user_id = ?');
    params.push(userId);
  }

  if (fromDate) {
    conditions.push('DATE(r.date) >= DATE(?)');
    params.push(fromDate);
  }

  if (toDate) {
    conditions.push('DATE(r.date) <= DATE(?)');
    params.push(toDate);
  }

  if (q) {
    conditions.push('(r.item_name LIKE ? OR r.description LIKE ? OR r.location LIKE ?)');
    const searchTerm = `%${q}%`;
    params.push(searchTerm, searchTerm, searchTerm);
  }

  let query = `
    SELECT r.*, u.name as user_name, u.phone as user_phone, u.email as user_email 
    FROM reports r 
    JOIN lostandfound u ON r.user_id = u.id
  `;

  if (conditions.length > 0) {
    query += ` WHERE ${conditions.join(' AND ')}`;
  }

  query += ' ORDER BY r.created_at DESC LIMIT 100';

  db.query(query, params, (err, results) => {
    if (err) {
      console.log('Database Error in get reports:', err);
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
  photo: report.photo_path ? toUrl(report.photo_path) : null,
      userId: report.user_id,
      id: report.id.toString(),
      createdAt: report.created_at,
      userName: report.user_name,
      userPhone: report.user_phone,
      userEmail: report.user_email,
      status: report.status || 'open'
    }));
    
    res.json({ reports: formattedReports });
  });
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
  photo: report.photo_path ? toUrl(report.photo_path) : null,
        userId: report.user_id,
        id: report.id.toString(),
        createdAt: report.created_at,
        status: report.status || 'open'
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

// ✅ CLAIM: Submit claim for a report
app.post('/api/reports/:reportId/claims', (req, res) => {
  const reportId = req.params.reportId;
  const { claimerId, message } = req.body;

  if (!claimerId || !message) {
    return res.status(400).json({ error: 'Claimer ID and message are required' });
  }

  db.query('SELECT * FROM reports WHERE id = ?', [reportId], (err, reportResults) => {
    if (err) {
      console.error('Claim lookup error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (reportResults.length === 0) {
      return res.status(404).json({ error: 'Report not found' });
    }

    const report = reportResults[0];

    if (report.user_id === Number(claimerId)) {
      return res.status(400).json({ error: 'You cannot claim your own report' });
    }

    db.query(
      'INSERT INTO claims (report_id, claimer_id, message) VALUES (?, ?, ?)',
      [reportId, claimerId, message],
      (insertErr, result) => {
        if (insertErr) {
          console.error('Claim insert error:', insertErr);
          return res.status(500).json({ error: 'Failed to submit claim' });
        }

        updateReportStatus(reportId, 'pending_claim');
        notifyUser(
          report.user_id,
          'New claim received',
          `Someone submitted a claim for "${report.item_name}". Please review it.`,
          null
        );
        notifyUser(
          claimerId,
          'Claim submitted',
          `Your claim for "${report.item_name}" has been sent to the owner.`,
          null
        );

        res.json({
          message: 'Claim submitted successfully',
          claimId: result.insertId
        });
      }
    );
  });
});

// ✅ CLAIM: Get claims for a report (for owner/admin)
app.get('/api/reports/:reportId/claims', (req, res) => {
  const reportId = req.params.reportId;

  const query = `
    SELECT c.*, u.name as claimer_name, u.email as claimer_email, u.phone as claimer_phone
    FROM claims c
    JOIN lostandfound u ON c.claimer_id = u.id
    WHERE c.report_id = ?
    ORDER BY c.created_at DESC
  `;

  db.query(query, [reportId], (err, results) => {
    if (err) {
      console.error('Get report claims error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ claims: results });
  });
});

// ✅ CLAIM: Get claims submitted by a user
app.get('/api/user/claims/:userId', (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT c.*, r.item_name, r.type as report_type, r.status as report_status
    FROM claims c
    JOIN reports r ON c.report_id = r.id
    WHERE c.claimer_id = ?
    ORDER BY c.created_at DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Get user claims error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ claims: results });
  });
});

// ✅ CLAIM: Get incoming claims for user's reports
app.get('/api/user/incoming-claims/:userId', (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT c.*, r.item_name, r.type as report_type, u.name as claimer_name, u.email as claimer_email, u.phone as claimer_phone
    FROM claims c
    JOIN reports r ON c.report_id = r.id
    JOIN lostandfound u ON c.claimer_id = u.id
    WHERE r.user_id = ?
    ORDER BY c.created_at DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Get incoming claims error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ claims: results });
  });
});

// ✅ CLAIM: Update claim status
app.patch('/api/claims/:claimId/status', (req, res) => {
  const claimId = req.params.claimId;
  const { status } = req.body;
  const allowedStatuses = ['pending', 'approved', 'rejected'];

  if (!allowedStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const lookupQuery = `
    SELECT c.*, r.item_name, r.user_id as owner_id 
    FROM claims c 
    JOIN reports r ON c.report_id = r.id 
    WHERE c.id = ?
  `;

  db.query(lookupQuery, [claimId], (err, results) => {
    if (err) {
      console.error('Claim status lookup error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Claim not found' });
    }

    const claim = results[0];

    db.query('UPDATE claims SET status = ? WHERE id = ?', [status, claimId], (updateErr) => {
      if (updateErr) {
        console.error('Claim status update error:', updateErr);
        return res.status(500).json({ error: 'Failed to update claim status' });
      }

      if (status === 'approved') {
        updateReportStatus(claim.report_id, 'closed');
        notifyUser(
          claim.claimer_id,
          'Claim approved',
          `Your claim for "${claim.item_name}" was approved.`,
          null
        );
      } else if (status === 'rejected') {
        updateReportStatus(claim.report_id, 'open');
        notifyUser(
          claim.claimer_id,
          'Claim rejected',
          `Your claim for "${claim.item_name}" was rejected.`,
          null
        );
      } else {
        updateReportStatus(claim.report_id, 'pending_claim');
      }

      res.json({ message: 'Claim status updated successfully' });
    });
  });
});

// ✅ MATCHES: Fetch potential matches for current user
app.get('/api/matches/:userId', (req, res) => {
  const userId = req.params.userId;

  const query = `
    SELECT 
      r.id as report_id,
      r.item_name as report_item_name,
      r.type as report_type,
      r.category as report_category,
      r.location as report_location,
      r.date as report_date,
      m.id as match_id,
      m.item_name as match_item_name,
      m.type as match_type,
      m.location as match_location,
      m.date as match_date,
      m.photo_path as match_photo_path,
      m.user_id as match_user_id,
      u.name as match_user_name,
      u.phone as match_user_phone,
      u.email as match_user_email
    FROM reports r
    JOIN reports m ON m.type != r.type
      AND m.category = r.category
      AND m.user_id != r.user_id
      AND (m.location LIKE CONCAT('%', r.location, '%') OR r.location LIKE CONCAT('%', m.location, '%'))
      AND ABS(TIMESTAMPDIFF(DAY, m.date, r.date)) <= 30
      AND (m.status IS NULL OR m.status != 'closed')
    JOIN lostandfound u ON m.user_id = u.id
    WHERE r.user_id = ?
      AND (r.status IS NULL OR r.status != 'closed')
    ORDER BY ABS(TIMESTAMPDIFF(DAY, m.date, r.date)) ASC
    LIMIT 20
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Matches lookup error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    const matches = results.map(row => ({
      baseReport: {
        id: row.report_id,
        itemName: row.report_item_name,
        type: row.report_type,
        category: row.report_category,
        location: row.report_location,
        date: row.report_date
      },
      match: {
        id: row.match_id,
        itemName: row.match_item_name,
        type: row.match_type,
        location: row.match_location,
        date: row.match_date,
  photo: row.match_photo_path ? toUrl(row.match_photo_path) : null,
        userId: row.match_user_id,
        userName: row.match_user_name,
        userPhone: row.match_user_phone,
        userEmail: row.match_user_email
      }
    }));

    res.json({ matches });
  });
});

// ✅ NOTIFICATIONS: List notifications for user
app.get('/api/notifications/:userId', (req, res) => {
  const userId = req.params.userId;

  db.query(
    'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
    [userId],
    (err, results) => {
      if (err) {
        console.error('Notifications fetch error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({ notifications: results });
    }
  );
});

// ✅ NOTIFICATIONS: Mark notification as read
app.patch('/api/notifications/:notificationId/read', (req, res) => {
  const notificationId = req.params.notificationId;

  db.query(
    'UPDATE notifications SET is_read = 1 WHERE id = ?',
    [notificationId],
    (err) => {
      if (err) {
        console.error('Notification update error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({ message: 'Notification marked as read' });
    }
  );
});

// ✅ ADMIN: Admin Login - WORKING FIX
app.post('/api/admin/login', rateLimit(15 * 60 * 1000, 10), (req, res) => {
  const { username, password } = req.body;
  
  console.log('Admin login attempt:', username, password);
  
  // Simple admin authentication - FROM ENV VARIABLES
  if (username === (process.env.ADMIN_USERNAME || 'admin') && password === (process.env.ADMIN_PASSWORD || 'admin123')) {
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
  photo: report.photo_path ? toUrl(report.photo_path) : null,
        userId: report.user_id,
        id: report.id.toString(),
        createdAt: report.created_at,
        userName: report.user_name,
        userPhone: report.user_phone,
      userEmail: report.user_email,
      status: report.status || 'open'
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
      
      // Convert stored relative paths to full encoded URLs for each user
      const users = (results || []).map(u => {
        if (u.profile_picture) {
          u.profile_picture = toUrl(u.profile_picture);
        }
        return u;
      });

      res.json({ users });
    }
  );
});

// ✅ ADMIN: Get dashboard statistics
app.get('/api/admin/stats', (req, res) => {
  const queries = [
    'SELECT COUNT(*) as total FROM lostandfound',
    'SELECT COUNT(*) as total FROM reports',
    'SELECT COUNT(*) as total FROM claims',
    'SELECT COUNT(*) as total FROM claims WHERE status = "pending"',
    'SELECT COUNT(*) as total FROM claims WHERE status = "approved"',
    'SELECT COUNT(*) as total FROM reports WHERE type = "lost"',
    'SELECT COUNT(*) as total FROM reports WHERE type = "found"'
  ];

  Promise.all(queries.map(q => new Promise((resolve, reject) => {
    db.query(q, (err, result) => {
      if (err) {
        console.error('Stats query error:', err);
        resolve(0); // Return 0 on error instead of rejecting
      } else {
        resolve(result[0].total);
      }
    });
  })))
  .then(results => {
    res.json({
      totalUsers: results[0] || 0,
      totalReports: results[1] || 0,
      totalClaims: results[2] || 0,
      pendingClaims: results[3] || 0,
      approvedClaims: results[4] || 0,
      lostReports: results[5] || 0,
      foundReports: results[6] || 0
    });
  })
  .catch(err => {
    console.error('Stats error:', err);
    res.json({
      totalUsers: 0,
      totalReports: 0,
      totalClaims: 0,
      pendingClaims: 0,
      approvedClaims: 0,
      lostReports: 0,
      foundReports: 0
    });
  });
});

// ✅ ADMIN: Get all claims
app.get('/api/admin/claims', (req, res) => {
  const query = `
    SELECT c.*, 
      r.item_name, r.type as report_type, r.user_id as report_owner_id,
      u1.name as claimer_name, u1.email as claimer_email, u1.phone as claimer_phone,
      u2.name as owner_name, u2.email as owner_email, u2.phone as owner_phone
    FROM claims c
    JOIN reports r ON c.report_id = r.id
    JOIN lostandfound u1 ON c.claimer_id = u1.id
    JOIN lostandfound u2 ON r.user_id = u2.id
    ORDER BY c.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Admin claims fetch error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ claims: results });
  });
});

// ✅ ADMIN: Update claim status
app.patch('/api/admin/claims/:claimId/status', (req, res) => {
  const claimId = req.params.claimId;
  const { status } = req.body;
  const allowedStatuses = ['pending', 'approved', 'rejected'];

  if (!allowedStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const lookupQuery = `
    SELECT c.*, r.item_name, r.user_id as owner_id 
    FROM claims c 
    JOIN reports r ON c.report_id = r.id 
    WHERE c.id = ?
  `;

  db.query(lookupQuery, [claimId], (err, results) => {
    if (err) {
      console.error('Claim status lookup error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Claim not found' });
    }

    const claim = results[0];

    db.query('UPDATE claims SET status = ? WHERE id = ?', [status, claimId], (updateErr) => {
      if (updateErr) {
        console.error('Claim status update error:', updateErr);
        return res.status(500).json({ error: 'Failed to update claim status' });
      }

      if (status === 'approved') {
        updateReportStatus(claim.report_id, 'closed');
        notifyUser(
          claim.claimer_id,
          'Claim approved by Admin',
          `Admin approved your claim for "${claim.item_name}".`,
          null
        );
        notifyUser(
          claim.owner_id,
          'Claim approved',
          `Admin approved a claim for your report "${claim.item_name}".`,
          null
        );
      } else if (status === 'rejected') {
        updateReportStatus(claim.report_id, 'open');
        notifyUser(
          claim.claimer_id,
          'Claim rejected by Admin',
          `Admin rejected your claim for "${claim.item_name}".`,
          null
        );
      }

      res.json({ message: 'Claim status updated by admin' });
    });
  });
});

// ✅ ADMIN: Delete user
app.delete('/api/admin/users/:userId', (req, res) => {
  const userId = req.params.userId;
  
  // First delete user's reports
  db.query('DELETE FROM reports WHERE user_id = ?', [userId], (err1) => {
    if (err1) {
      console.error('Delete user reports error:', err1);
      return res.status(500).json({ error: 'Failed to delete user reports' });
    }
    
    // Delete user's claims
    db.query('DELETE FROM claims WHERE claimer_id = ?', [userId], (err2) => {
      if (err2) {
        console.error('Delete user claims error:', err2);
        return res.status(500).json({ error: 'Failed to delete user claims' });
      }
      
      // Delete user's notifications
      db.query('DELETE FROM notifications WHERE user_id = ?', [userId], (err3) => {
        if (err3) {
          console.error('Delete user notifications error:', err3);
          return res.status(500).json({ error: 'Failed to delete user notifications' });
        }
        
        // Finally delete user
        db.query('DELETE FROM lostandfound WHERE id = ?', [userId], (err4) => {
          if (err4) {
            console.error('Delete user error:', err4);
            return res.status(500).json({ error: 'Failed to delete user' });
          }
          
          res.json({ message: 'User deleted successfully by admin' });
        });
      });
    });
  });
});

// ✅ ADMIN: Update report
app.patch('/api/admin/reports/:reportId', (req, res) => {
  const reportId = req.params.reportId;
  const { itemName, description, location, category, status } = req.body;
  
  const updates = [];
  const params = [];
  
  if (itemName) {
    updates.push('item_name = ?');
    params.push(itemName);
  }
  if (description) {
    updates.push('description = ?');
    params.push(description);
  }
  if (location) {
    updates.push('location = ?');
    params.push(location);
  }
  if (category) {
    updates.push('category = ?');
    params.push(category);
  }
  if (status) {
    updates.push('status = ?');
    params.push(status);
  }
  
  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }
  
  params.push(reportId);
  const query = `UPDATE reports SET ${updates.join(', ')} WHERE id = ?`;
  
  db.query(query, params, (err) => {
    if (err) {
      console.error('Admin update report error:', err);
      return res.status(500).json({ error: 'Failed to update report' });
    }
    
    res.json({ message: 'Report updated successfully by admin' });
  });
});

// ✅ ADMIN: Send notification to user(s)
app.post('/api/admin/notify', (req, res) => {
  const { userIds, title, message } = req.body;
  
  if (!userIds || !Array.isArray(userIds) || !title || !message) {
    return res.status(400).json({ error: 'Invalid request data' });
  }
  
  const queries = userIds.map(userId => {
    return new Promise((resolve, reject) => {
      notifyUser(userId, title, message, null);
      resolve();
    });
  });
  
  Promise.all(queries)
    .then(() => {
      res.json({ message: `Notifications sent to ${userIds.length} user(s)` });
    })
    .catch(err => {
      console.error('Admin notify error:', err);
      res.status(500).json({ error: 'Failed to send notifications' });
    });
});

// ✅ SUPPORT CHAT: Send message (user or admin)
app.post('/api/support/send', (req, res) => {
  const { userId, message, senderType } = req.body;
  
  if (!userId || !message || !senderType) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  if (!['user', 'admin'].includes(senderType)) {
    return res.status(400).json({ error: 'Invalid sender type' });
  }
  
  db.query(
    'INSERT INTO support_chats (user_id, message, sender_type) VALUES (?, ?, ?)',
    [userId, message, senderType],
    (err, result) => {
      if (err) {
        console.error('Support chat send error:', err);
        return res.status(500).json({ error: 'Failed to send message' });
      }
      
      res.json({ 
        message: 'Message sent successfully',
        chatId: result.insertId
      });
    }
  );
});

// ✅ SUPPORT CHAT: Get chat history for a user
app.get('/api/support/history/:userId', (req, res) => {
  const userId = req.params.userId;
  
  db.query(
    'SELECT * FROM support_chats WHERE user_id = ? ORDER BY created_at ASC',
    [userId],
    (err, results) => {
      if (err) {
        console.error('Support chat history error:', err);
        return res.status(500).json({ error: 'Failed to fetch chat history' });
      }
      
      res.json({ messages: results });
    }
  );
});

// ✅ SUPPORT CHAT: Mark messages as read
app.patch('/api/support/read/:userId', (req, res) => {
  const userId = req.params.userId;
  const { senderType } = req.body; // 'user' or 'admin'
  
  db.query(
    'UPDATE support_chats SET is_read = 1 WHERE user_id = ? AND sender_type = ? AND is_read = 0',
    [userId, senderType],
    (err) => {
      if (err) {
        console.error('Support chat mark read error:', err);
        return res.status(500).json({ error: 'Failed to mark messages as read' });
      }
      
      res.json({ message: 'Messages marked as read' });
    }
  );
});

// ✅ SUPPORT CHAT: Get unread count for user
app.get('/api/support/unread/:userId', (req, res) => {
  const userId = req.params.userId;
  
  db.query(
    'SELECT COUNT(*) as count FROM support_chats WHERE user_id = ? AND sender_type = "admin" AND is_read = 0',
    [userId],
    (err, results) => {
      if (err) {
        console.error('Support unread count error:', err);
        return res.status(500).json({ error: 'Failed to get unread count' });
      }
      
      res.json({ unreadCount: results[0].count });
    }
  );
});

// ✅ ADMIN SUPPORT: Get all user chats
app.get('/api/admin/support/chats', (req, res) => {
  const query = `
    SELECT 
      u.id as user_id,
      u.name as user_name,
      u.email as user_email,
      COUNT(CASE WHEN sc.sender_type = 'user' AND sc.is_read = 0 THEN 1 END) as unread_count,
      MAX(sc.created_at) as last_message_time
    FROM lostandfound u
    LEFT JOIN support_chats sc ON u.id = sc.user_id
    GROUP BY u.id, u.name, u.email
    HAVING COUNT(sc.id) > 0
    ORDER BY last_message_time DESC
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Admin support chats error:', err);
      return res.status(500).json({ error: 'Failed to fetch support chats' });
    }
    
    res.json({ users: results });
  });
});

// ✅ ADMIN SUPPORT: Get total unread count
app.get('/api/admin/support/unread-total', (req, res) => {
  db.query(
    'SELECT COUNT(*) as count FROM support_chats WHERE sender_type = "user" AND is_read = 0',
    (err, results) => {
      if (err) {
        console.error('Admin support unread total error:', err);
        return res.status(500).json({ error: 'Failed to get unread count' });
      }
      
      res.json({ totalUnread: results[0].count });
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});