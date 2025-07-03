require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

app.use(cors());
app.use(express.json());

// SQLite setup
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) throw err;
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    verified INTEGER DEFAULT 0,
    verification_token TEXT
  )`);
});

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Helper: send verification email
function sendVerificationEmail(email, token) {
  const link = `${BASE_URL}/verify?token=${token}`;
  return transporter.sendMail({
    from: `"Code and Caffeine" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify your email',
    html: `<p>Click <a href="${link}">here</a> to verify your email for Code and Caffeine.</p>`
  });
}

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required.' });
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (user) return res.status(400).json({ error: 'Email already registered.' });
    const hash = await bcrypt.hash(password, 10);
    const verification_token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1d' });
    db.run('INSERT INTO users (name, email, password, verification_token) VALUES (?, ?, ?, ?)', [name, email, hash, verification_token], async function(err) {
      if (err) return res.status(500).json({ error: 'Database error.' });
      try {
        await sendVerificationEmail(email, verification_token);
        res.json({ success: true, message: 'Signup successful. Please check your email to verify your account.' });
      } catch (e) {
        res.status(500).json({ error: 'Failed to send verification email.' });
      }
    });
  });
});

// Email verification endpoint
app.get('/verify', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Invalid verification link.');
  let email;
  try {
    email = jwt.verify(token, JWT_SECRET).email;
  } catch {
    return res.status(400).send('Invalid or expired token.');
  }
  db.run('UPDATE users SET verified = 1, verification_token = NULL WHERE email = ?', [email], function(err) {
    if (err || this.changes === 0) return res.status(400).send('Verification failed.');
    res.send('Email verified! You can now sign in.');
  });
});

// Signin endpoint
app.post('/api/signin', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'All fields required.' });
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) return res.status(400).json({ error: 'Invalid credentials.' });
    if (!user.verified) return res.status(403).json({ error: 'Please verify your email first.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials.' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, name: user.name });
  });
});

app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
}); 