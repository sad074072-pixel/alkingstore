const express = require('express');
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });

// Database setup
const db = new sqlite3.Database('./database.db', (err) => {
  if (err) console.error(err);
  else console.log('Connected to SQLite database');
});

// Create tables
db.serialize(() => {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Scripts table
  db.run(`
    CREATE TABLE IF NOT EXISTS scripts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      user_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      file_size INTEGER,
      downloads INTEGER DEFAULT 0,
      license_key TEXT UNIQUE,
      ip_address TEXT,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.userId = decoded.id;
    next();
  });
};

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run(
    'INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
    [email, username, hashedPassword],
    function (err) {
      if (err) {
        return res.status(400).json({ message: 'Email or username already exists' });
      }
      res.status(201).json({ message: 'User registered successfully', userId: this.lastID });
    }
  );
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful', token, user: { id: user.id, email: user.email, username: user.username } });
  });
});

// ============ SCRIPT ROUTES ============

// Upload script
app.post('/api/scripts/upload', verifyToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

  const { title, description, ip_address } = req.body;
  const licenseKey = 'BS-' + Math.random().toString(36).substr(2, 9).toUpperCase() + '-' + Date.now();

  db.run(
    'INSERT INTO scripts (title, description, user_id, filename, original_filename, file_size, license_key, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [title || 'Untitled', description || '', req.userId, req.file.filename, req.file.originalname, req.file.size, licenseKey, ip_address || 'N/A'],
    function (err) {
      if (err) {
        return res.status(500).json({ message: 'Error saving script' });
      }
      res.status(201).json({
        message: 'Script uploaded successfully',
        script: {
          id: this.lastID,
          title: title || 'Untitled',
          filename: req.file.filename,
          licenseKey: licenseKey,
          fileSize: req.file.size
        }
      });
    }
  );
});

// Get all scripts (for homepage)
app.get('/api/scripts', (req, res) => {
  db.all(
    'SELECT id, title, description, file_size, downloads, license_key, ip_address, created_at FROM scripts WHERE status = ? ORDER BY created_at DESC',
    ['active'],
    (err, scripts) => {
      if (err) {
        return res.status(500).json({ message: 'Error fetching scripts' });
      }
      res.json(scripts);
    }
  );
});

// Get user's scripts
app.get('/api/scripts/user', verifyToken, (req, res) => {
  db.all(
    'SELECT id, title, description, file_size, downloads, license_key, status, created_at FROM scripts WHERE user_id = ? ORDER BY created_at DESC',
    [req.userId],
    (err, scripts) => {
      if (err) {
        return res.status(500).json({ message: 'Error fetching scripts' });
      }
      res.json(scripts);
    }
  );
});

// Download script
app.get('/api/scripts/download/:id', (req, res) => {
  db.get('SELECT * FROM scripts WHERE id = ? AND status = ?', [req.params.id, 'active'], (err, script) => {
    if (err || !script) {
      return res.status(404).json({ message: 'Script not found' });
    }

    // Increment downloads
    db.run('UPDATE scripts SET downloads = downloads + 1 WHERE id = ?', [req.params.id]);

    const filePath = path.join(__dirname, 'uploads', script.filename);
    res.download(filePath, script.original_filename);
  });
});

// Delete script
app.delete('/api/scripts/:id', verifyToken, (req, res) => {
  db.get('SELECT * FROM scripts WHERE id = ? AND user_id = ?', [req.params.id, req.userId], (err, script) => {
    if (err || !script) {
      return res.status(404).json({ message: 'Script not found or unauthorized' });
    }

    // Delete file
    const filePath = path.join(__dirname, 'uploads', script.filename);
    fs.unlink(filePath, (err) => {
      if (err) console.error(err);
    });

    // Delete from database
    db.run('UPDATE scripts SET status = ? WHERE id = ?', ['deleted', req.params.id], (err) => {
      if (err) {
        return res.status(500).json({ message: 'Error deleting script' });
      }
      res.json({ message: 'Script deleted successfully' });
    });
  });
});

// Update script info
app.put('/api/scripts/:id', verifyToken, (req, res) => {
  const { title, description, ip_address } = req.body;

  db.run(
    'UPDATE scripts SET title = ?, description = ?, ip_address = ? WHERE id = ? AND user_id = ?',
    [title, description, ip_address, req.params.id, req.userId],
    function (err) {
      if (err) {
        return res.status(500).json({ message: 'Error updating script' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ message: 'Script not found or unauthorized' });
      }
      res.json({ message: 'Script updated successfully' });
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`ALKING STORE server running on port ${PORT}`);
});
