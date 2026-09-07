// ============================================================
// server.js – Complete Payment Backend (Single File)
// ============================================================

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import axios from 'axios';

// Load environment variables
dotenv.config();

// ---------- Configuration ----------
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_SENDER_EMAIL = process.env.BREVO_SENDER_EMAIL;
const BREVO_SENDER_NAME = process.env.BREVO_SENDER_NAME;
const FRONTEND_URL = process.env.FRONTEND_URL || '*';

// Validate required env vars
const required = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'BREVO_API_KEY', 'JWT_SECRET'];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`❌ Missing ${key} in environment variables`);
    process.exit(1);
  }
}

// ---------- Supabase Client ----------
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ---------- Brevo Service (email) ----------
const brevo = {
  async sendOTP(email, otpCode, userName) {
    try {
      await axios.post(
        'https://api.brevo.com/v3/smtp/email',
        {
          sender: { email: BREVO_SENDER_EMAIL, name: BREVO_SENDER_NAME },
          to: [{ email }],
          subject: 'Your Payment Verification Code',
          htmlContent: `
            <h2>Payment Verification</h2>
            <p>Hello ${userName || 'User'},</p>
            <p>Your OTP for the $2,000.00 USD payment is:</p>
            <h1 style="background:#eef4ff;padding:20px;text-align:center;letter-spacing:5px;">${otpCode}</h1>
            <p>This code expires in 10 minutes.</p>
            <p>If you didn't request this, ignore it.</p>
          `,
        },
        { headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json' } }
      );
      return { success: true };
    } catch (err) {
      console.error('Brevo OTP error:', err.response?.data || err.message);
      throw new Error('Failed to send OTP');
    }
  },

  async sendConfirmation(email, userName, amount, receiver) {
    try {
      await axios.post(
        'https://api.brevo.com/v3/smtp/email',
        {
          sender: { email: BREVO_SENDER_EMAIL, name: BREVO_SENDER_NAME },
          to: [{ email }],
          subject: 'Payment Completed Successfully',
          htmlContent: `
            <h2>✅ Payment Confirmed</h2>
            <p>Hello ${userName || 'User'},</p>
            <p>Your payment of <strong>$${amount.toFixed(2)} USD</strong> is complete.</p>
            <p><strong>Bank:</strong> ${receiver.bankName}</p>
            <p><strong>Account:</strong> ${receiver.accountNumber}</p>
          `,
        },
        { headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json' } }
      );
      return { success: true };
    } catch (err) {
      console.error('Brevo confirmation error:', err.response?.data || err.message);
      throw new Error('Failed to send confirmation');
    }
  }
};

// ---------- Payment Service (Supabase) ----------
const paymentService = {
  async getOrCreateUser(email, name) {
    let { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .maybeSingle();
    if (error) throw new Error('Database error');
    if (!user) {
      const { data: newUser, error: insertErr } = await supabase
        .from('users')
        .insert({ email, name: name || 'User' })
        .select()
        .single();
      if (insertErr) throw new Error('Failed to create user');
      user = newUser;
    }
    return user;
  },

  async createPayment(userId, receiver) {
    const { data, error } = await supabase
      .from('payments')
      .insert({
        user_id: userId,
        amount: 2000,
        method: 'bank',
        receiver_bank: receiver.bankName,
        receiver_account_holder: receiver.accountHolder,
        receiver_account_number: receiver.accountNumber,
        receiver_sort_code: receiver.sortCode,
        status: 'pending',
      })
      .select()
      .single();
    if (error) throw new Error('Failed to create payment');
    return data;
  },

  async storeOTP(userId, otpCode) {
    const expiresAt = new Date(Date.now() + 10 * 60000).toISOString();
    const { error } = await supabase
      .from('otp_codes')
      .insert({ user_id: userId, otp_code: otpCode, expires_at: expiresAt });
    if (error) throw new Error('Failed to store OTP');
  },

  async verifyOTP(userId, otpCode) {
    const { data, error } = await supabase
      .from('otp_codes')
      .select('*')
      .eq('user_id', userId)
      .eq('otp_code', otpCode)
      .eq('is_used', false)
      .gte('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error || !data) return { valid: false };
    // mark as used
    await supabase.from('otp_codes').update({ is_used: true }).eq('id', data.id);
    return { valid: true };
  },

  async updatePaymentStatus(paymentId, status, verified = false) {
    const payload = { status, updated_at: new Date().toISOString() };
    if (verified) payload.otp_verified = true;
    const { data, error } = await supabase
      .from('payments')
      .update(payload)
      .eq('id', paymentId)
      .select()
      .single();
    if (error) throw new Error('Failed to update payment');
    return data;
  },

  async getPayment(paymentId) {
    const { data, error } = await supabase
      .from('payments')
      .select('*')
      .eq('id', paymentId)
      .maybeSingle();
    if (error) throw new Error('Failed to fetch payment');
    return data;
  }
};

// ---------- Receiver Details (fixed) ----------
const RECEIVER = {
  bankName: 'Banco Nacional de Costa Rica',
  accountHolder: 'Juan Diego Alvarado Chacon',
  accountNumber: 'CR20015105820010208270',
  sortCode: '506'
};

// ---------- Express App ----------
const app = express();

// Security & middleware
app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json());

// ---------- Routes ----------

// Health check
app.get('/health', (req, res) => res.json({ status: 'OK', time: new Date().toISOString() }));

// 1. Authenticate (get JWT)
app.post('/api/auth', async (req, res) => {
  try {
    const { email, name } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const user = await paymentService.getOrCreateUser(email, name);
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Initiate payment (send OTP)
app.post('/api/payments/initiate', async (req, res) => {
  try {
    const { email, name } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const user = await paymentService.getOrCreateUser(email, name);
    const payment = await paymentService.createPayment(user.id, RECEIVER);
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    await paymentService.storeOTP(user.id, otp);
    await brevo.sendOTP(email, otp, user.name);
    res.json({
      success: true,
      paymentId: payment.id,
      amount: payment.amount,
      status: payment.status,
      receiver: RECEIVER,
      message: 'OTP sent to your email'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Verify OTP and complete payment
app.post('/api/payments/verify-complete', async (req, res) => {
  try {
    const { paymentId, otpCode, email } = req.body;
    if (!paymentId || !otpCode || !email)
      return res.status(400).json({ error: 'Missing fields' });
    const user = await paymentService.getOrCreateUser(email);
    const { valid } = await paymentService.verifyOTP(user.id, otpCode);
    if (!valid) return res.status(400).json({ error: 'Invalid or expired OTP' });
    const payment = await paymentService.updatePaymentStatus(paymentId, 'completed', true);
    await brevo.sendConfirmation(email, user.name, payment.amount, RECEIVER);
    res.json({ success: true, message: 'Payment completed', payment: { id: payment.id, status: payment.status } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Get payment status (requires auth)
app.get('/api/payments/status/:paymentId', async (req, res) => {
  try {
    // Optional: validate JWT from Authorization header
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Authorization required' });
    const token = auth.split(' ')[1];
    try { jwt.verify(token, JWT_SECRET); } catch (e) { return res.status(403).json({ error: 'Invalid token' }); }

    const payment = await paymentService.getPayment(req.params.paymentId);
    if (!payment) return res.status(404).json({ error: 'Payment not found' });
    res.json({
      success: true,
      payment: {
        id: payment.id,
        amount: payment.amount,
        status: payment.status,
        method: payment.method,
        receiver: {
          bankName: payment.receiver_bank,
          accountHolder: payment.receiver_account_holder,
          accountNumber: payment.receiver_account_number,
          sortCode: payment.receiver_sort_code
        },
        createdAt: payment.created_at,
        updatedAt: payment.updated_at
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Resend OTP
app.post('/api/payments/resend-otp', async (req, res) => {
  try {
    const { email, paymentId } = req.body;
    if (!email || !paymentId) return res.status(400).json({ error: 'Missing fields' });
    const user = await paymentService.getOrCreateUser(email);
    const payment = await paymentService.getPayment(paymentId);
    if (!payment) return res.status(404).json({ error: 'Payment not found' });
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    await paymentService.storeOTP(user.id, otp);
    await brevo.sendOTP(email, otp, user.name);
    res.json({ success: true, message: 'OTP resent' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
