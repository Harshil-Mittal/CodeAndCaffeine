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
    otp TEXT,
    otp_expiry INTEGER
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

// Helper: generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper: send OTP email
function sendOTPEmail(email, otp, purpose = 'verify') {
  let subject, html;
  if (purpose === 'verify') {
    subject = 'Verify your email';
    html = `<p>Your Code and Caffeine verification OTP is: <b>${otp}</b></p>`;
  } else {
    subject = 'Password Reset OTP';
    html = `<p>Your Code and Caffeine password reset OTP is: <b>${otp}</b></p>`;
  }
  return transporter.sendMail({
    from: `"Code and Caffeine" <${process.env.EMAIL_USER}>`,
    to: email,
    subject,
    html
  });
}

// Signup endpoint (with OTP)
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required.' });
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (user) return res.status(400).json({ error: 'Email already registered.' });
    const hash = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const otp_expiry = Date.now() + 15 * 60 * 1000; // 15 min
    db.run('INSERT INTO users (name, email, password, otp, otp_expiry) VALUES (?, ?, ?, ?, ?)', [name, email, hash, otp, otp_expiry], async function(err) {
      if (err) return res.status(500).json({ error: 'Database error.' });
      try {
        await sendOTPEmail(email, otp, 'verify');
        res.json({ success: true, message: 'Signup successful. Please check your email for the OTP to verify your account.' });
      } catch (e) {
        res.status(500).json({ error: 'Failed to send OTP email.' });
      }
    });
  });
});

// Verify OTP endpoint (for email verification)
app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required.' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user) return res.status(400).json({ error: 'User not found.' });
    if (user.verified) return res.status(400).json({ error: 'Already verified.' });
    if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP.' });
    if (Date.now() > user.otp_expiry) return res.status(400).json({ error: 'OTP expired.' });
    db.run('UPDATE users SET verified = 1, otp = NULL, otp_expiry = NULL WHERE email = ?', [email], function(err) {
      if (err) return res.status(500).json({ error: 'Database error.' });
      res.json({ success: true, message: 'Email verified! You can now sign in.' });
    });
  });
});

// Resend OTP endpoint (for verification)
app.post('/api/resend-otp', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) return res.status(400).json({ error: 'User not found.' });
    if (user.verified) return res.status(400).json({ error: 'Already verified.' });
    const otp = generateOTP();
    const otp_expiry = Date.now() + 15 * 60 * 1000;
    db.run('UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?', [otp, otp_expiry, email], async function(err) {
      if (err) return res.status(500).json({ error: 'Database error.' });
      try {
        await sendOTPEmail(email, otp, 'verify');
        res.json({ success: true, message: 'OTP resent.' });
      } catch (e) {
        res.status(500).json({ error: 'Failed to send OTP email.' });
      }
    });
  });
});

// Forgot password: request OTP
app.post('/api/request-reset', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) return res.status(400).json({ error: 'User not found.' });
    const otp = generateOTP();
    const otp_expiry = Date.now() + 15 * 60 * 1000;
    db.run('UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?', [otp, otp_expiry, email], async function(err) {
      if (err) return res.status(500).json({ error: 'Database error.' });
      try {
        await sendOTPEmail(email, otp, 'reset');
        res.json({ success: true, message: 'OTP sent to your email.' });
      } catch (e) {
        res.status(500).json({ error: 'Failed to send OTP email.' });
      }
    });
  });
});

// Forgot password: verify OTP
app.post('/api/verify-reset-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required.' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user) return res.status(400).json({ error: 'User not found.' });
    if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP.' });
    if (Date.now() > user.otp_expiry) return res.status(400).json({ error: 'OTP expired.' });
    res.json({ success: true, message: 'OTP verified.' });
  });
});

// Forgot password: reset password
app.post('/api/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) return res.status(400).json({ error: 'All fields required.' });
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) return res.status(400).json({ error: 'User not found.' });
    if (user.otp !== otp) return res.status(400).json({ error: 'Invalid OTP.' });
    if (Date.now() > user.otp_expiry) return res.status(400).json({ error: 'OTP expired.' });
    const hash = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ?, otp = NULL, otp_expiry = NULL WHERE email = ?', [hash, email], function(err) {
      if (err) return res.status(500).json({ error: 'Database error.' });
      res.json({ success: true, message: 'Password reset successful.' });
    });
  });
});

// Signin endpoint (unchanged)
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