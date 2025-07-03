require('dotenv').config();
console.log('EMAIL_USER:', process.env.EMAIL_USER);
console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? '***set***' : '***not set***');

const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Test email (run once to check setup)
transporter.sendMail({
  from: `"Code and Caffeine" <${process.env.EMAIL_USER}>`,
  to: process.env.EMAIL_USER, // send to yourself for testing
  subject: 'Test Email',
  text: 'This is a test email from Code and Caffeine backend.'
}, (err, info) => {
  if (err) {
    console.error('Test email error:', err);
  } else {
    console.log('Test email sent:', info.response);
  }
});