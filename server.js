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
      is_admin INTEGER DEFAULT 0,
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
      price REAL DEFAULT 0,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  // User products table (شراء المنتجات)
  db.run(`
    CREATE TABLE IF NOT EXISTS user_products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      script_id INTEGER NOT NULL,
      license_key TEXT,
      purchased_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(script_id) REFERENCES scripts(id),
      UNIQUE(user_id, script_id)
    )
  `);

  // Transactions table (سجل المعاملات)
  db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      script_id INTEGER NOT NULL,
      amount REAL,
      transaction_type TEXT,
      status TEXT DEFAULT 'completed',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(script_id) REFERENCES scripts(id)
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

// Middleware to verify admin
const verifyAdmin = (req, res, next) => {
  verifyToken(req, res, () => {
    db.get('SELECT is_admin FROM users WHERE id = ?', [req.userId], (err, user) => {
      if (err || !user || !user.is_admin) {
        return res.status(403).json({ message: 'Admin access required' });
      }
      next();
    });
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
    res.json({ 
      message: 'Login successful', 
      token, 
      user: { 
        id: user.id, 
        email: user.email, 
        username: user.username,
        is_admin: user.is_admin 
      } 
    });
  });
});

// ============ SCRIPT ROUTES ============

// Upload script (Admin only)
app.post('/api/scripts/upload', verifyAdmin, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

  const { title, description, ip_address, price } = req.body;
  const licenseKey = 'AS-' + Math.random().toString(36).substr(2, 9).toUpperCase() + '-' + Date.now();

  db.run(
    'INSERT INTO scripts (title, description, user_id, filename, original_filename, file_size, license_key, ip_address, price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [title || 'Untitled', description || '', req.userId, req.file.filename, req.file.originalname, req.file.size, licenseKey, ip_address || 'N/A', price || 0],
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
          fileSize: req.file.size,
          price: price || 0
        }
      });
    }
  );
});

// Get all scripts (for homepage)
app.get('/api/scripts', (req, res) => {
  db.all(
    'SELECT id, title, description, file_size, downloads, license_key, ip_address, price, created_at FROM scripts WHERE status = ? ORDER BY created_at DESC',
    ['active'],
    (err, scripts) => {
      if (err) {
        return res.status(500).json({ message: 'Error fetching scripts' });
      }
      res.json(scripts);
    }
  );
});

// Get user's uploaded scripts
app.get('/api/scripts/user/uploaded', verifyToken, (req, res) => {
  db.all(
    'SELECT id, title, description, file_size, downloads, license_key, price, status, created_at FROM scripts WHERE user_id = ? ORDER BY created_at DESC',
    [req.userId],
    (err, scripts) => {
      if (err) {
        return res.status(500).json({ message: 'Error fetching scripts' });
      }
      res.json(scripts);
    }
  );
});

// Get user's purchased scripts
app.get('/api/scripts/user/purchased', verifyToken, (req, res) => {
  db.all(
    `SELECT s.id, s.title, s.description, s.file_size, s.downloads, s.license_key, s.price, s.created_at, up.license_key as user_license_key, up.purchased_at
     FROM scripts s
     INNER JOIN user_products up ON s.id = up.script_id
     WHERE up.user_id = ? AND s.status = ?
     ORDER BY up.purchased_at DESC`,
    [req.userId, 'active'],
    (err, scripts) => {
      if (err) {
        return res.status(500).json({ message: 'Error fetching purchased scripts' });
      }
      res.json(scripts);
    }
  );
});

// Give product to user (Admin)
app.post('/api/admin/give-product', verifyAdmin, (req, res) => {
  const { user_id, script_id } = req.body;

  if (!user_id || !script_id) {
    return res.status(400).json({ message: 'user_id and script_id are required' });
  }

  // Check if user and script exist
  db.get('SELECT id FROM users WHERE id = ?', [user_id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ message: 'User not found' });
    }

    db.get('SELECT id, license_key FROM scripts WHERE id = ?', [script_id], (err, script) => {
      if (err || !script) {
        return res.status(404).json({ message: 'Script not found' });
      }

      // Add product to user
      db.run(
        'INSERT OR REPLACE INTO user_products (user_id, script_id, license_key) VALUES (?, ?, ?)',
        [user_id, script_id, script.license_key],
        function (err) {
          if (err) {
            return res.status(500).json({ message: 'Error giving product to user' });
          }

          res.status(201).json({ 
            message: 'Product given to user successfully',
            product: {
              user_id: user_id,
              script_id: script_id,
              license_key: script.license_key
            }
          });
        }
      );
    });
  });
});

// Buy product
app.post('/api/scripts/buy/:id', verifyToken, (req, res) => {
  const scriptId = req.params.id;
  const userId = req.userId;

  db.get('SELECT id, price, license_key FROM scripts WHERE id = ? AND status = ?', [scriptId, 'active'], (err, script) => {
    if (err || !script) {
      return res.status(404).json({ message: 'Script not found' });
    }

    if (script.price === 0) {
      return res.status(400).json({ message: 'This script is free, please download instead' });
    }

    // Check if already purchased
    db.get('SELECT id FROM user_products WHERE user_id = ? AND script_id = ?', [userId, scriptId], (err, product) => {
      if (product) {
        return res.status(400).json({ message: 'You already own this product' });
      }

      // Give product to user
      db.run(
        'INSERT INTO user_products (user_id, script_id, license_key) VALUES (?, ?, ?)',
        [userId, scriptId, script.license_key],
        function (err) {
          if (err) {
            return res.status(500).json({ message: 'Error purchasing product' });
          }

          // Create transaction record
          db.run(
            'INSERT INTO transactions (user_id, script_id, amount, transaction_type) VALUES (?, ?, ?, ?)',
            [userId, scriptId, script.price, 'purchase']
          );

          res.status(201).json({
            message: 'Product purchased successfully',
            product: {
              id: scriptId,
              license_key: script.license_key,
              price: script.price
            }
          });
        }
      );
    });
  });
});

// Download script (Free or purchased)
app.get('/api/scripts/download/:id', verifyToken, (req, res) => {
  const scriptId = req.params.id;
  const userId = req.userId;

  db.get('SELECT * FROM scripts WHERE id = ? AND status = ?', [scriptId, 'active'], (err, script) => {
    if (err || !script) {
      return res.status(404).json({ message: 'Script not found' });
    }

    // Check if free or user owns it
    if (script.price > 0) {
      db.get('SELECT id FROM user_products WHERE user_id = ? AND script_id = ?', [userId, scriptId], (err, product) => {
        if (!product) {
          return res.status(403).json({ message: 'You need to purchase this product first' });
        }
        downloadFile();
      });
    } else {
      downloadFile();
    }

    function downloadFile() {
      // Increment downloads
      db.run('UPDATE scripts SET downloads = downloads + 1 WHERE id = ?', [scriptId]);

      const filePath = path.join(__dirname, 'uploads', script.filename);
      res.download(filePath, script.original_filename);
    }
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
  const { title, description, ip_address, price } = req.body;

  db.run(
    'UPDATE scripts SET title = ?, description = ?, ip_address = ?, price = ? WHERE id = ? AND user_id = ?',
    [title, description, ip_address, price, req.params.id, req.userId],
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

// Get all users (Admin)
app.get('/api/admin/users', verifyAdmin, (req, res) => {
  db.all(
    'SELECT id, email, username, is_admin, created_at FROM users ORDER BY created_at DESC',
    [],
    (err, users) => {
      if (err) {
        return res.status(500).json({ message: 'Error fetching users' });
      }
      res.json(users);
    }
  );
});

// Remove product from user (Admin)
app.delete('/api/admin/remove-product/:user_id/:script_id', verifyAdmin, (req, res) => {
  const { user_id, script_id } = req.params;

  db.run(
    'DELETE FROM user_products WHERE user_id = ? AND script_id = ?',
    [user_id, script_id],
    function (err) {
      if (err) {
        return res.status(500).json({ message: 'Error removing product' });
      }
      res.json({ message: 'Product removed from user successfully' });
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`ALKING STORE server running on port ${PORT}`);
});
