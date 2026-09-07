// ============================================================
// server.js - Main Express Server (UPDATED)
// ============================================================
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================
// CONFIGURATION
// ============================================================
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const JWT_EXPIRY = '7d';

// Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ ERROR: Supabase URL or Key not set in environment variables!');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Brevo Email (via SMTP)
const emailConfig = {
    host: process.env.BREVO_HOST || 'smtp-relay.brevo.com',
    port: parseInt(process.env.BREVO_PORT) || 587,
    secure: false,
    auth: {
        user: process.env.BREVO_USER || 'your-brevo-email@example.com',
        pass: process.env.BREVO_PASS || 'your-brevo-smtp-key'
    }
};

const transporter = nodemailer.createTransport(emailConfig);

// ============================================================
// MIDDLEWARE
// ============================================================

// Security headers
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

// CORS - Allow multiple origins
const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:5500',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5500',
    'https://*.netlify.app',
    'https://*.netlify.com',
    process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        // Check if origin matches any allowed pattern
        const isAllowed = allowedOrigins.some(pattern => {
            if (pattern.includes('*')) {
                const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
                return regex.test(origin);
            }
            return pattern === origin;
        });
        
        if (isAllowed) {
            callback(null, true);
        } else {
            console.warn('CORS blocked origin:', origin);
            callback(null, true); // Allow anyway for development
        }
    },
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
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Stricter rate limit for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'Too many authentication attempts, please try again later.'
});
app.use('/api/auth/', authLimiter);

// ============================================================
// DATABASE HELPERS (Supabase)
// ============================================================
const db = {
    users: {
        async create(userData) {
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
                    is_verified: false,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                }])
                .select()
                .single();

            if (error) throw new Error(`Supabase insert error: ${error.message}`);
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
        },

        async verifyUser(id) {
            const { data, error } = await supabase
                .from('users')
                .update({
                    is_verified: true,
                    email_verified_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                })
                .eq('id', id)
                .select()
                .single();

            if (error) throw new Error(`Supabase verify error: ${error.message}`);
            return data;
        }
    },

    otps: {
        async create(otpData) {
            const { data, error } = await supabase
                .from('otps')
                .insert([{
                    email: otpData.email,
                    otp_code: otpData.otpCode,
                    expires_at: otpData.expiresAt,
                    is_used: false,
                    created_at: new Date().toISOString()
                }])
                .select()
                .single();

            if (error) throw new Error(`Supabase OTP insert error: ${error.message}`);
            return data;
        },

        async findValid(email, otpCode) {
            const { data, error } = await supabase
                .from('otps')
                .select('*')
                .eq('email', email)
                .eq('otp_code', otpCode)
                .eq('is_used', false)
                .gt('expires_at', new Date().toISOString())
                .order('created_at', { ascending: false })
                .limit(1)
                .maybeSingle();

            if (error) throw new Error(`Supabase OTP find error: ${error.message}`);
            return data;
        },

        async markUsed(id) {
            const { data, error } = await supabase
                .from('otps')
                .update({
                    is_used: true,
                    used_at: new Date().toISOString()
                })
                .eq('id', id)
                .select()
                .single();

            if (error) throw new Error(`Supabase OTP update error: ${error.message}`);
            return data;
        }
    }
};

// ============================================================
// EMAIL SERVICE (Brevo)
// ============================================================
async function sendOTPEmail(email, otpCode, userName) {
    try {
        // Verify transporter connection
        await transporter.verify();
        
        const mailOptions = {
            from: process.env.BREVO_FROM_EMAIL || 'noreply@aags.org',
            to: email,
            subject: 'Verify Your AAGS Account',
            html: `
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
            `
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('✅ OTP email sent:', info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('❌ Email send error:', error);
        throw new Error('Failed to send verification email');
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

// ===== HEALTH CHECK =====
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        uptime: process.uptime(),
        version: '1.0.0',
        services: {
            supabase: supabaseUrl ? 'connected' : 'disconnected',
            email: emailConfig.auth.user ? 'configured' : 'not configured'
        }
    });
});

// Root endpoint for testing
app.get('/', (req, res) => {
    res.json({
        message: 'AAGS Backend API',
        version: '1.0.0',
        endpoints: {
            health: '/api/health',
            auth: {
                signup: 'POST /api/auth/signup',
                login: 'POST /api/auth/login',
                verifyOtp: 'POST /api/auth/verify-otp',
                resendOtp: 'POST /api/auth/resend-otp',
                verifyToken: 'POST /api/auth/verify-token'
            },
            user: {
                profile: 'GET /api/user/me',
                update: 'PUT /api/user/profile',
                changePassword: 'POST /api/user/change-password'
            }
        },
        docs: 'https://farm-aagsgithub-io.onrender.com/api/health'
    });
});

// ===== AUTH ROUTES =====

// SIGNUP
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

        // Check if user exists
        const existingUser = await db.users.findByEmail(email);
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'User with this email already exists'
            });
        }

        // Hash password
        const passwordHash = hashPassword(password);

        // Create user
        const user = await db.users.create({
            firstName,
            middleName,
            lastName,
            email,
            phone,
            dateOfBirth,
            gender,
            country,
            passwordHash
        });

        console.log(`✅ User created: ${user.id}`);

        // Generate OTP
        const otpCode = generateOTP();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

        // Save OTP
        await db.otps.create({
            email,
            otpCode,
            expiresAt: expiresAt.toISOString()
        });

        console.log(`📧 Sending OTP to: ${email}`);

        // Send OTP email via Brevo
        const userName = `${firstName} ${lastName}`;
        await sendOTPEmail(email, otpCode, userName);

        // Generate JWT token (for auto-login after verification)
        const token = generateToken(user);

        // Return success
        res.status(201).json({
            success: true,
            message: 'User created successfully. Please verify your email with the OTP sent.',
            data: {
                userId: user.id,
                email: user.email,
                name: `${user.first_name} ${user.last_name}`,
                token: token,
                isVerified: false
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

// VERIFY OTP
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

        // Find valid OTP
        const otpRecord = await db.otps.findValid(email, otpCode);

        if (!otpRecord) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired OTP code'
            });
        }

        // Find user
        const user = await db.users.findByEmail(email);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Mark OTP as used
        await db.otps.markUsed(otpRecord.id);

        // Verify user
        await db.users.verifyUser(user.id);

        // Generate new token after verification
        const token = generateToken(user);

        console.log(`✅ User verified: ${email}`);

        res.json({
            success: true,
            message: 'Email verified successfully!',
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

// RESEND OTP
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

        // Find user
        const user = await db.users.findByEmail(email);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.is_verified) {
            return res.status(400).json({
                success: false,
                message: 'User is already verified'
            });
        }

        // Generate new OTP
        const otpCode = generateOTP();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

        // Save OTP
        await db.otps.create({
            email,
            otpCode,
            expiresAt: expiresAt.toISOString()
        });

        // Send OTP email
        const userName = `${user.first_name} ${user.last_name}`;
        await sendOTPEmail(email, otpCode, userName);

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

// LOGIN
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

        // Find user
        const user = await db.users.findByEmail(email);
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

        // Check if verified
        if (!user.is_verified) {
            console.log(`⚠️ User not verified: ${email}`);

            // Generate and send new OTP
            const otpCode = generateOTP();
            const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

            await db.otps.create({
                email,
                otpCode,
                expiresAt: expiresAt.toISOString()
            });

            const userName = `${user.first_name} ${user.last_name}`;
            await sendOTPEmail(email, otpCode, userName);

            return res.status(403).json({
                success: false,
                message: 'Email not verified. A new OTP has been sent to your email.',
                requiresVerification: true,
                email: email
            });
        }

        // Generate token
        const token = generateToken(user);

        // Update last login
        await db.users.update(user.id, {
            last_login_at: new Date().toISOString()
        });

        console.log(`✅ Login successful: ${email}`);

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

// ===== PROTECTED ROUTES =====

// GET CURRENT USER
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

// UPDATE USER PROFILE
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { firstName, middleName, lastName, phone, dateOfBirth, gender, country } = req.body;

        const updates = {};
        if (firstName) updates.first_name = firstName;
        if (middleName !== undefined) updates.middle_name = middleName;
        if (lastName) updates.last_name = lastName;
        if (phone) updates.phone = phone;
        if (dateOfBirth) updates.date_of_birth = dateOfBirth;
        if (gender) updates.gender = gender;
        if (country) updates.country = country;

        const user = await db.users.update(req.user.userId, updates);

        res.json({
            success: true,
            message: 'Profile updated successfully',
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
                isVerified: user.is_verified
            }
        });

    } catch (error) {
        console.error('❌ Update profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update profile',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// CHANGE PASSWORD
app.post('/api/user/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Current password and new password are required'
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 8 characters'
            });
        }

        const user = await db.users.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Verify current password
        const isValid = comparePassword(currentPassword, user.password_hash);
        if (!isValid) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Hash new password
        const newPasswordHash = hashPassword(newPassword);

        // Update password
        await db.users.update(user.id, {
            password_hash: newPasswordHash
        });

        res.json({
            success: true,
            message: 'Password changed successfully'
        });

    } catch (error) {
        console.error('❌ Change password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to change password',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ===== SYSTEM ROUTES =====

// Verify JWT token (for frontend)
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

        // Check if user still exists
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
    console.log('🚀 AAGS Backend Server Running');
    console.log(`📍 Port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔐 JWT Secret: ${JWT_SECRET ? '✅ Set' : '❌ Not Set'}`);
    console.log(`📧 Brevo: ${emailConfig.auth.user ? '✅ Configured' : '❌ Not Configured'}`);
    console.log(`🗄️  Supabase: ${supabaseUrl ? '✅ Connected' : '❌ Not Connected'}`);
    console.log(`🌐 Health Check: http://localhost:${PORT}/api/health`);
    console.log('========================================');
});

// ============================================================
// EXPORTS FOR TESTING
// ============================================================
module.exports = { app, db, generateOTP, hashPassword, comparePassword, generateToken, verifyToken };
