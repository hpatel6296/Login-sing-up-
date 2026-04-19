const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');

const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(express.json());
// Serve static client files (like our Loginpage.html and style.css)
app.use(express.static(path.join(__dirname))); 

// Initialize Database
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'), (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // Create the users table if it doesn't exist to store credentials securely
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login_type TEXT NOT NULL,
            identifier TEXT NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    }
});

// API Route for Login
app.post('/api/login', (req, res) => {
    setTimeout(() => {
        const { type, identifier, password, remember } = req.body;
        if (!identifier || !password) {
            return res.status(400).json({ success: false, message: 'Identifier and password are required' });
        }
        db.get('SELECT * FROM users WHERE login_type = ? AND identifier = ?', [type, identifier], (err, row) => {
            if (err) return res.status(500).json({ success: false, message: 'Database error' });
            if (row) {
                if (row.password === password) {
                    return res.json({ success: true, message: 'Login successful!', action: 'login' });
                } else {
                    return res.status(401).json({ success: false, message: 'Incorrect password' });
                }
            } else {
                return res.status(404).json({ success: false, message: 'Account not found. Please sign up.' });
            }
        });
    }, 600);
});

// API Route for Register
app.post('/api/register', (req, res) => {
    setTimeout(() => {
        const { type, identifier, password } = req.body;
        if (!identifier || !password) {
            return res.status(400).json({ success: false, message: 'Identifier and password are required' });
        }
        
        // Password Constraints Verification
        const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be 8+ chars with an uppercase, a number, and a special character.' 
            });
        }

        db.get('SELECT * FROM users WHERE login_type = ? AND identifier = ?', [type, identifier], (err, row) => {
            if (err) return res.status(500).json({ success: false, message: 'Database error' });
            if (row) {
                return res.status(409).json({ success: false, message: 'Account already exists! Please login.' });
            } else {
                db.run('INSERT INTO users (login_type, identifier, password) VALUES (?, ?, ?)', [type, identifier, password], function(err) {
                    if (err) return res.status(500).json({ success: false, message: 'Error creating user' });
                    return res.json({ success: true, message: 'Account created successfully!', action: 'register' });
                });
            }
        });
    }, 600);
});

// API Route for Reset Password
app.post('/api/reset', (req, res) => {
    setTimeout(() => {
        const { type, identifier, newPassword } = req.body;
        if (!identifier || !newPassword) {
            return res.status(400).json({ success: false, message: 'Identifier and new password required' });
        }
        
        const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({ success: false, message: 'Password must be 8+ chars with an uppercase, a number, and a special character.' });
        }

        db.get('SELECT * FROM users WHERE login_type = ? AND identifier = ?', [type, identifier], (err, row) => {
            if (err) return res.status(500).json({ success: false, message: 'Database error' });
            if (!row) {
                return res.status(404).json({ success: false, message: 'We cannot find an account with that information.' });
            } else {
                db.run('UPDATE users SET password = ? WHERE id = ?', [newPassword, row.id], function(err) {
                    if (err) return res.status(500).json({ success: false, message: 'Error updating password' });
                    return res.json({ success: true, message: 'Password reset successfully!' });
                });
            }
        });
    }, 600);
});

// Start Server
app.listen(port, () => {
    console.log(`\n=========================================`);
    console.log(`🚀 Server is running at http://localhost:${port}`);
    console.log(`🔗 VIEW PAGE: http://localhost:${port}/Loginpage.html`);
    console.log(`=========================================\n`);
});
