// ============================================================
// server.js - AAGS Backend Server
// User data is only saved AFTER email verification
// ============================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const SibApiV3Sdk = require('sib-api-v3-sdk');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================
// ENVIRONMENT VALIDATION
// ============================================================
const requiredEnvVars = [
    'SUPABASE_URL',
    'SUPABASE_SERVICE_KEY',
    'JWT_SECRET',
    'BREVO_API_KEY',
    'BREVO_FROM_EMAIL'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:');
    missingVars.forEach(varName => console.error(`   - ${varName}`));
    console.error('\n⚠️  Please set these variables in your .env file or Render dashboard.');
    process.exit(1);
}

// ============================================================
// CONFIGURATION
// ============================================================
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = '7d';

// Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;

const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: {
        autoRefreshToken: false,
        persistSession: false
    }
});

// Brevo API Configuration
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_FROM_EMAIL = process.env.BREVO_FROM_EMAIL;
const BREVO_FROM_NAME = process.env.BREVO_FROM_NAME || 'AAGS';

console.log('📧 Brevo API Key:', BREVO_API_KEY ? '✅ Configured' : '❌ Not Set');
console.log('📧 Brevo From Email:', BREVO_FROM_EMAIL || '❌ Not Set');

// Configure Brevo API
let brevoConfigured = false;
let apiInstance = null;

try {
    const defaultClient = SibApiV3Sdk.ApiClient.instance;
    const apiKeyAuth = defaultClient.authentications['api-key'];
    apiKeyAuth.apiKey = BREVO_API_KEY;
    
    apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
    brevoConfigured = true;
    console.log('✅ Brevo API configured successfully');
} catch (error) {
    console.error('❌ Failed to configure Brevo API:', error.message);
    brevoConfigured = false;
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
            styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
            fontSrc: ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "gnews.io", "*.gnews.io"],
            connectSrc: ["'self'", "gnews.io", "*.gnews.io"],
        },
    },
}));

app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
app.use((req, res, next) => {
    console.log(`📝 ${req.method} ${req.path} - ${req.ip}`);
    next();
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'Too many authentication attempts, please try again later.'
});
app.use('/api/auth/', authLimiter);

// ============================================================
// DATABASE HELPERS (Supabase)
// ============================================================

// Temporary storage for pending users (before email verification)
// In production, this should be in Supabase with a cleanup job
const pendingUsers = new Map(); // email -> { userData, otpCode, expiresAt }

const db = {
    // Pending users (temporary storage before verification)
    pendingUsers: {
        async create(userData) {
            console.log('📝 Storing pending user:', userData.email);
            const key = userData.email.toLowerCase();
            pendingUsers.set(key, {
                userData: userData,
                otpCode: userData.otpCode,
                expiresAt: userData.expiresAt,
                createdAt: new Date().toISOString()
            });
            
            // Clean up old entries (older than 15 minutes)
            const now = new Date();
            for (const [k, v] of pendingUsers.entries()) {
                if (new Date(v.expiresAt) < now) {
                    pendingUsers.delete(k);
                }
            }
            
            return { success: true };
        },

        async findByEmail(email) {
            const key = email.toLowerCase();
            const record = pendingUsers.get(key);
            if (!record) return null;
            
            // Check if expired
            if (new Date(record.expiresAt) < new Date()) {
                pendingUsers.delete(key);
                return null;
            }
            
            return record;
        },

        async deleteByEmail(email) {
            const key = email.toLowerCase();
            pendingUsers.delete(key);
            return { success: true };
        }
    },

    // Users table (only after verification)
    users: {
        async create(userData) {
            console.log('📝 Creating verified user:', userData.email);
            
            const { data, error } = await supabase
                .from('users')
                .insert([{
                    email: userData.email,
                    password_hash: userData.passwordHash,
                    first_name: userData.firstName,
                    middle_name: userData.middleName || null,
                    last_name: userData.lastName,
                    phone: userData.phone,
                    date_of_birth: userData.dateOfBirth,
                    gender: userData.gender || null,
                    country: userData.country,
                    is_verified: true,
                    email_verified_at: new Date().toISOString(),
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                }])
                .select()
                .single();

            if (error) {
                console.error('❌ Supabase insert error:', error);
                throw new Error(`Supabase insert error: ${error.message}`);
            }
            
            console.log('✅ User created successfully:', data.id);
            return data;
        },

        async findByEmail(email) {
            const { data, error } = await supabase
                .from('users')
                .select('*')
                .eq('email', email)
                .maybeSingle();

            if (error) throw new Error(`Supabase find error: ${error.message}`);
            return data;
        },

        async findById(id) {
            const { data, error } = await supabase
                .from('users')
                .select('*')
                .eq('id', id)
                .maybeSingle();

            if (error) throw new Error(`Supabase find error: ${error.message}`);
            return data;
        },

        async update(id, updates) {
            updates.updated_at = new Date().toISOString();
            const { data, error } = await supabase
                .from('users')
                .update(updates)
                .eq('id', id)
                .select()
                .single();

            if (error) throw new Error(`Supabase update error: ${error.message}`);
            return data;
        }
    }
};

// ============================================================
// EMAIL SERVICE (Brevo REST API)
// ============================================================
async function sendOTPEmail(email, otpCode, userName) {
    try {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email || !emailRegex.test(email)) {
            console.error('❌ Invalid email address:', email);
            return { 
                success: false, 
                error: 'Invalid email address format',
                code: 'INVALID_EMAIL'
            };
        }

        console.log('📧 Sending OTP to:', email);
        console.log('📧 Sender from:', BREVO_FROM_EMAIL);
        
        if (!brevoConfigured || !apiInstance) {
            console.error('❌ Brevo API not configured properly');
            return { success: false, error: 'Email service not configured' };
        }

        const cleanEmail = email.trim().toLowerCase();

        const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
        
        sendSmtpEmail.subject = 'Verify Your AAGS Account';
        sendSmtpEmail.htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f7f4f0; border-radius: 12px;">
                <div style="background-color: #ffffff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08);">
                    <div style="text-align: center; margin-bottom: 20px;">
                        <h1 style="color: #1a4a3a; font-size: 28px; margin: 0;">AAGS<span style="color: #c6a15b;">.</span></h1>
                        <p style="color: #5a6b6b; margin: 5px 0 0;">American Agricultural Grant Services</p>
                    </div>
                    <h2 style="color: #1a4a3a; font-size: 22px; text-align: center;">Verify Your Email Address</h2>
                    <p style="color: #1e2b2b; font-size: 16px; line-height: 1.6;">
                        Hello ${userName || 'there'},
                    </p>
                    <p style="color: #1e2b2b; font-size: 16px; line-height: 1.6;">
                        Thank you for signing up for AAGS. Please use the verification code below to complete your registration:
                    </p>
                    <div style="text-align: center; margin: 30px 0;">
                        <div style="display: inline-block; background-color: #f7f2e9; padding: 15px 40px; border-radius: 8px; font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #1a4a3a; border: 2px solid #c6a15b;">
                            ${otpCode}
                        </div>
                    </div>
                    <p style="color: #5a6b6b; font-size: 14px; text-align: center;">
                        This code will expire in 15 minutes.
                    </p>
                    <p style="color: #5a6b6b; font-size: 14px; text-align: center; margin-top: 20px;">
                        If you didn't create an account with AAGS, please ignore this email.
                    </p>
                    <hr style="border: none; border-top: 1px solid #e9ecec; margin: 20px 0;">
                    <p style="color: #5a6b6b; font-size: 12px; text-align: center;">
                        &copy; 2026 American Agricultural Grant Services. All rights reserved.
                    </p>
                </div>
            </div>
        `;
        
        sendSmtpEmail.sender = { 
            name: BREVO_FROM_NAME, 
            email: BREVO_FROM_EMAIL 
        };
        
        sendSmtpEmail.to = [{ 
            email: cleanEmail, 
            name: userName || 'User' 
        }];

        const response = await apiInstance.sendTransacEmail(sendSmtpEmail);
        console.log('✅ OTP email sent via Brevo API:', response.messageId);
        return { success: true, messageId: response.messageId };
        
    } catch (error) {
        console.error('❌ Brevo API error:', error);
        
        let errorMessage = error.message;
        let errorCode = null;
        
        if (error.response?.body) {
            console.error('Error details:', error.response.body);
            if (error.response.body.message) {
                errorMessage = error.response.body.message;
            }
            if (error.response.body.code) {
                errorCode = error.response.body.code;
            }
        }
        
        return { 
            success: false, 
            error: errorMessage,
            code: errorCode
        };
    }
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateToken(user) {
    return jwt.sign(
        {
            userId: user.id,
            email: user.email,
            name: `${user.first_name} ${user.last_name}`,
            isVerified: user.is_verified
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY }
    );
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

function hashPassword(password) {
    return bcrypt.hashSync(password, 12);
}

function comparePassword(password, hash) {
    return bcrypt.compareSync(password, hash);
}

// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Authentication token required' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    req.user = decoded;
    next();
}

// ============================================================
// API ROUTES
// ============================================================

// HEALTH CHECK
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        services: {
            supabase: supabaseUrl ? 'connected' : 'disconnected',
            brevo: brevoConfigured ? 'configured' : 'not configured'
        }
    });
});

app.get('/', (req, res) => {
    res.json({
        message: 'AAGS Backend API',
        version: '1.0.0',
        endpoints: {
            health: '/api/health',
            signup: 'POST /api/auth/signup',
            verifyOtp: 'POST /api/auth/verify-otp',
            resendOtp: 'POST /api/auth/resend-otp',
            login: 'POST /api/auth/login',
            verifyToken: 'POST /api/auth/verify-token'
        }
    });
});

// ============================================================
// SIGNUP - Only stores pending user, NOT in database
// ============================================================
app.post('/api/auth/signup', async (req, res) => {
    try {
        const {
            firstName,
            middleName,
            lastName,
            email,
            phone,
            dateOfBirth,
            gender,
            country,
            password
        } = req.body;

        console.log(`📝 Signup attempt for: ${email}`);

        // Validation
        if (!firstName || !lastName || !email || !phone || !dateOfBirth || !country || !password) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please enter a valid email address'
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        // Check if user already exists and is verified
        const existingUser = await db.users.findByEmail(cleanEmail);
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'User with this email already exists'
            });
        }

        // Check if there's a pending user
        const pendingUser = await db.pendingUsers.findByEmail(cleanEmail);
        if (pendingUser) {
            // Delete old pending user so they can retry
            await db.pendingUsers.deleteByEmail(cleanEmail);
        }

        // Generate OTP
        const otpCode = generateOTP();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

        // Hash password
        const passwordHash = hashPassword(password);

        // Store pending user data (temporary, NOT in database yet)
        const userData = {
            firstName,
            middleName,
            lastName,
            email: cleanEmail,
            phone,
            dateOfBirth,
            gender,
            country,
            passwordHash,
            otpCode,
            expiresAt: expiresAt.toISOString()
        };

        await db.pendingUsers.create(userData);

        // Send OTP email
        const userName = `${firstName} ${lastName}`;
        const emailResult = await sendOTPEmail(cleanEmail, otpCode, userName);

        // Return success - user is pending verification
        res.status(201).json({
            success: true,
            message: emailResult.success 
                ? 'Please verify your email with the OTP sent.'
                : 'Please check your email for the OTP (if you don\'t see it, check spam).',
            data: {
                email: cleanEmail,
                name: userName,
                requiresVerification: true,
                otpCode: process.env.NODE_ENV === 'development' ? otpCode : undefined
            }
        });

    } catch (error) {
        console.error('❌ Signup error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error during signup',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================================
// VERIFY OTP - ONLY HERE user gets saved to database
// ============================================================
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otpCode } = req.body;

        console.log(`🔐 OTP verification attempt for: ${email}`);

        if (!email || !otpCode) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP code are required'
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        // Find pending user
        const pendingRecord = await db.pendingUsers.findByEmail(cleanEmail);
        if (!pendingRecord) {
            return res.status(400).json({
                success: false,
                message: 'No pending signup found. Please sign up again.'
            });
        }

        // Verify OTP
        if (pendingRecord.otpCode !== otpCode) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP code. Please try again.'
            });
        }

        // Check if expired
        if (new Date(pendingRecord.expiresAt) < new Date()) {
            await db.pendingUsers.deleteByEmail(cleanEmail);
            return res.status(400).json({
                success: false,
                message: 'OTP has expired. Please request a new one.'
            });
        }

        // OTP is valid - NOW create the user in database
        const userData = pendingRecord.userData;
        
        const user = await db.users.create({
            firstName: userData.firstName,
            middleName: userData.middleName,
            lastName: userData.lastName,
            email: userData.email,
            phone: userData.phone,
            dateOfBirth: userData.dateOfBirth,
            gender: userData.gender,
            country: userData.country,
            passwordHash: userData.passwordHash
        });

        // Delete pending record
        await db.pendingUsers.deleteByEmail(cleanEmail);

        // Generate JWT token
        const token = generateToken(user);

        console.log(`✅ User verified and created: ${cleanEmail}`);

        res.json({
            success: true,
            message: 'Email verified successfully! Account created.',
            data: {
                userId: user.id,
                email: user.email,
                name: `${user.first_name} ${user.last_name}`,
                token: token,
                isVerified: true
            }
        });

    } catch (error) {
        console.error('❌ OTP verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error during verification',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================================
// RESEND OTP
// ============================================================
app.post('/api/auth/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;

        console.log(`📧 Resend OTP for: ${email}`);

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        // Find pending user
        const pendingRecord = await db.pendingUsers.findByEmail(cleanEmail);
        if (!pendingRecord) {
            return res.status(400).json({
                success: false,
                message: 'No pending signup found. Please sign up again.'
            });
        }

        // Generate new OTP
        const newOtpCode = generateOTP();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

        // Update pending record
        pendingRecord.otpCode = newOtpCode;
        pendingRecord.expiresAt = expiresAt.toISOString();

        // Re-save (delete and create new)
        await db.pendingUsers.deleteByEmail(cleanEmail);
        await db.pendingUsers.create({
            ...pendingRecord.userData,
            otpCode: newOtpCode,
            expiresAt: expiresAt.toISOString()
        });

        // Send new OTP email
        const userName = `${pendingRecord.userData.firstName} ${pendingRecord.userData.lastName}`;
        await sendOTPEmail(cleanEmail, newOtpCode, userName);

        res.json({
            success: true,
            message: 'New OTP sent to your email'
        });

    } catch (error) {
        console.error('❌ Resend OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to resend OTP',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================================
// LOGIN
// ============================================================
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        console.log(`🔐 Login attempt for: ${email}`);

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        // Check if user exists in database (only verified users are here)
        const user = await db.users.findByEmail(cleanEmail);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Check password
        const isValid = comparePassword(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Generate token
        const token = generateToken(user);

        // Update last login
        await db.users.update(user.id, {
            last_login_at: new Date().toISOString()
        });

        console.log(`✅ Login successful: ${cleanEmail}`);

        res.json({
            success: true,
            message: 'Login successful',
            data: {
                userId: user.id,
                email: user.email,
                name: `${user.first_name} ${user.last_name}`,
                token: token,
                isVerified: user.is_verified
            }
        });

    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error during login',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================================
// VERIFY TOKEN
// ============================================================
app.post('/api/auth/verify-token', async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({
                success: false,
                message: 'Token is required'
            });
        }

        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }

        const user = await db.users.findById(decoded.userId);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User no longer exists'
            });
        }

        res.json({
            success: true,
            message: 'Token is valid',
            data: {
                userId: decoded.userId,
                email: decoded.email,
                name: decoded.name,
                isVerified: decoded.isVerified
            }
        });

    } catch (error) {
        console.error('❌ Verify token error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to verify token',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================================
// GET USER
// ============================================================
app.get('/api/user/me', authenticateToken, async (req, res) => {
    try {
        const user = await db.users.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            data: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                middleName: user.middle_name,
                lastName: user.last_name,
                phone: user.phone,
                dateOfBirth: user.date_of_birth,
                gender: user.gender,
                country: user.country,
                isVerified: user.is_verified,
                createdAt: user.created_at,
                lastLoginAt: user.last_login_at
            }
        });

    } catch (error) {
        console.error('❌ Get user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user data',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ============================================================
// ERROR HANDLING
// ============================================================
app.use((req, res) => {
    console.log(`⚠️ 404 Not Found: ${req.method} ${req.path}`);
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, () => {
    console.log('========================================');
    console.log('🚀 AAGS Backend Server');
    console.log(`📍 Port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔐 JWT: ${JWT_SECRET ? '✅ Configured' : '❌ Not Set'}`);
    console.log(`📧 Brevo: ${BREVO_API_KEY ? '✅ Configured' : '❌ Not Set'}`);
    console.log(`🗄️  Supabase: ${supabaseUrl ? '✅ Connected' : '❌ Not Connected'}`);
    console.log('========================================');
});

module.exports = { app, db, generateOTP, hashPassword, comparePassword, generateToken, verifyToken };
