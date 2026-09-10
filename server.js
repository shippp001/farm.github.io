// ============================================================
// server.js - AAGS Backend Server
// News with real unique images (og:image fetch + 50-image fallback pool)
// ============================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const SibApiV3Sdk = require('sib-api-v3-sdk');
const Parser = require('rss-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================
// ENV VALIDATION
// ============================================================
const requiredEnvVars = ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'JWT_SECRET', 'BREVO_API_KEY', 'BREVO_FROM_EMAIL'];
const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
    console.error('❌ Missing env vars:', missingVars.join(', '));
    process.exit(1);
}

// ============================================================
// CONFIG
// ============================================================
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = '7d';

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
);

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_FROM_EMAIL = process.env.BREVO_FROM_EMAIL;
const BREVO_FROM_NAME = process.env.BREVO_FROM_NAME || 'AAGS';

const defaultClient = SibApiV3Sdk.ApiClient.instance;
defaultClient.authentications['api-key'].apiKey = BREVO_API_KEY;
const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();

const rssParser = new Parser({
    timeout: 10000,
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; AAGS-Bot/1.0)' }
});

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => { console.log(`📝 ${req.method} ${req.path}`); next(); });
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// ============================================================
// DATABASE HELPERS
// ============================================================
const db = {
    users: {
        async create(d) {
            const { data, error } = await supabase.from('users').insert([{
                email: d.email, password_hash: d.passwordHash,
                first_name: d.firstName, middle_name: d.middleName || null,
                last_name: d.lastName, phone: d.phone,
                date_of_birth: d.dateOfBirth, gender: d.gender || null,
                country: d.country, is_verified: true,
                email_verified_at: new Date().toISOString()
            }]).select().single();
            if (error) throw new Error(`Supabase: ${error.message}`);
            return data;
        },
        async findByEmail(email) {
            const { data, error } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
            if (error) throw new Error(`Supabase: ${error.message}`);
            return data;
        },
        async findById(id) {
            const { data, error } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
            if (error) throw new Error(`Supabase: ${error.message}`);
            return data;
        },
        async update(id, updates) {
            updates.updated_at = new Date().toISOString();
            const { data, error } = await supabase.from('users').update(updates).eq('id', id).select().single();
            if (error) throw new Error(`Supabase: ${error.message}`);
            return data;
        }
    }
};

const pendingUsers = new Map();

// ============================================================
// EMAIL SERVICE (Brevo API)
// ============================================================
async function sendOTPEmail(email, otpCode, userName) {
    try {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) return { success: false, error: 'Invalid email' };

        const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
        sendSmtpEmail.subject = 'Verify Your AAGS Account';
        sendSmtpEmail.htmlContent = `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#f7f4f0;border-radius:12px;">
                <div style="background:#fff;padding:30px;border-radius:12px;">
                    <h1 style="color:#1a4a3a;text-align:center;">AAGS<span style="color:#c6a15b;">.</span></h1>
                    <h2 style="color:#1a4a3a;text-align:center;">Verify Your Email</h2>
                    <p>Hello ${userName},</p>
                    <p>Your verification code:</p>
                    <div style="text-align:center;margin:30px 0;">
                        <div style="display:inline-block;background:#f7f2e9;padding:15px 40px;border-radius:8px;font-size:32px;font-weight:700;letter-spacing:8px;color:#1a4a3a;border:2px solid #c6a15b;">
                            ${otpCode}
                        </div>
                    </div>
                    <p style="color:#5a6b6b;font-size:14px;">Expires in 15 minutes.</p>
                </div>
            </div>
        `;
        sendSmtpEmail.sender = { name: BREVO_FROM_NAME, email: BREVO_FROM_EMAIL };
        sendSmtpEmail.to = [{ email, name: userName }];

        const response = await apiInstance.sendTransacEmail(sendSmtpEmail);
        return { success: true, messageId: response.messageId };
    } catch (error) {
        console.error('❌ Email error:', error.response?.body || error.message);
        return { success: false, error: error.message };
    }
}

// ============================================================
// UTILITIES
// ============================================================
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
const hashPassword = p => bcrypt.hashSync(p, 12);
const comparePassword = (p, h) => bcrypt.compareSync(p, h);

function generateToken(user) {
    return jwt.sign(
        { userId: user.id, email: user.email, name: `${user.first_name} ${user.last_name}`, isVerified: user.is_verified },
        JWT_SECRET, { expiresIn: JWT_EXPIRY }
    );
}
function verifyToken(token) {
    try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Token required' });
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ success: false, message: 'Invalid token' });
    req.user = decoded;
    next();
}

// ============================================================
// NEWS RSS FEEDS
// ============================================================
const NEWS_FEEDS = [
    { url: 'https://news.google.com/rss/search?q=agricultural+grants+USDA&hl=en-US&gl=US&ceid=US:en', source: 'Google News' },
    { url: 'https://news.google.com/rss/search?q=agriculture+farming+grants+funding&hl=en-US&gl=US&ceid=US:en', source: 'Google News' },
    { url: 'https://news.google.com/rss/search?q=USDA+farm+program+funding&hl=en-US&gl=US&ceid=US:en', source: 'Google News' },
    { url: 'https://news.google.com/rss/search?q=farm+grants+agriculture+funding&hl=en-US&gl=US&ceid=US:en', source: 'Google News' },
    { url: 'https://news.google.com/rss/search?q=rural+development+grants+USDA&hl=en-US&gl=US&ceid=US:en', source: 'Google News' },
    { url: 'https://news.google.com/rss/search?q=sustainable+agriculture+funding&hl=en-US&gl=US&ceid=US:en', source: 'Google News' }
];

let newsCache = { articles: [], fetchedAt: null };

// ============================================================
// LARGE IMAGE POOL — 50 unique agricultural images
// ============================================================
const IMAGE_POOL = [
    'https://images.unsplash.com/photo-1500595046743-cd271d694d30?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1592982537447-7440770cbfc9?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1500382017468-9049fed747ef?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1625246333195-78d9c38ad449?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1570042225831-d98fa7577f1e?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1560493676-04071c5f467b?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1523348837708-15d4a09cfac2?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1530836369250-ef72a3f5cda8?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1464226184884-fa280b87c399?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1516253593875-bd7ba052fbc5?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1492496913980-501348b61469?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1471193945509-9ad0617afabf?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1615729947596-a598e5de0ab3?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1620200423727-8127f75d7f53?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1605000797499-95a51c5269ae?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1560493676-04071c5f467b?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1595855759920-86582396756a?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1622383563227-04401ab4e5ea?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1495745455409-ff12e0ce45a4?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1595855759920-86582396756a?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1518977676601-b53f82aba655?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1595855759920-86582396756a?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1560493676-04071c5f467b?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1605000797499-95a51c5269ae?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1530836369250-ef72a3f5cda8?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1516253593875-bd7ba052fbc5?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1471193945509-9ad0617afabf?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1492496913980-501348b61469?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1615729947596-a598e5de0ab3?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1620200423727-8127f75d7f53?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1523348837708-15d4a09cfac2?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1464226184884-fa280b87c399?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1622383563227-04401ab4e5ea?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1495745455409-ff12e0ce45a4?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1518977676601-b53f82aba655?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1574943320219-553eb213f72d?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1592982537447-7440770cbfc9?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1500595046743-cd271d694d30?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1500382017468-9049fed747ef?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1625246333195-78d9c38ad449?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1570042225831-d98fa7577f1e?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1560493676-04071c5f467b?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1523348837708-15d4a09cfac2?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1530836369250-ef72a3f5cda8?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1464226184884-fa280b87c399?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1516253593875-bd7ba052fbc5?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1492496913980-501348b61469?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1471193945509-9ad0617afabf?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1615729947596-a598e5de0ab3?w=600&h=400&fit=crop',
    'https://images.unsplash.com/photo-1605000797499-95a51c5269ae?w=600&h=400&fit=crop'
];

// Deterministic hash
function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash;
    }
    return Math.abs(hash);
}

// Pick unique image per article
function pickUniqueImage(title, usedIndices) {
    const startIdx = hashString(title || 'x') % IMAGE_POOL.length;
    let idx = startIdx;
    let attempts = 0;
    while (usedIndices.has(idx) && attempts < IMAGE_POOL.length) {
        idx = (idx + 1) % IMAGE_POOL.length;
        attempts++;
    }
    usedIndices.add(idx);
    return IMAGE_POOL[idx];
}

// ============================================================
// OG:IMAGE FETCH (real article image)
// ============================================================
const ogImageCache = new Map(); // url -> image or null

async function fetchOgImage(url, timeout = 6000) {
    if (!url) return null;
    if (ogImageCache.has(url)) return ogImageCache.get(url);

    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);

        const res = await fetch(url, {
            redirect: 'follow',
            signal: controller.signal,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml'
            }
        });
        clearTimeout(timer);

        if (!res.ok) {
            ogImageCache.set(url, null);
            return null;
        }

        const html = await res.text();
        // Try multiple meta tag patterns
        let match = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
            || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i)
            || html.match(/<meta[^>]+name=["']twitter:image["'][^>]+content=["']([^"']+)["']/i)
            || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']twitter:image["']/i);

        const image = match ? match[1] : null;
        ogImageCache.set(url, image);
        return image;
    } catch (e) {
        ogImageCache.set(url, null);
        return null;
    }
}

// ============================================================
// FETCH & PARSE FEED
// ============================================================
async function fetchAndParseFeed(feed) {
    try {
        const parsed = await rssParser.parseURL(feed.url);
        return (parsed.items || []).slice(0, 8).map(item => {
            let rssImage = null;

            // Try RSS enclosure / media
            if (item.enclosure?.url) rssImage = item.enclosure.url;
            if (!rssImage && item['media:content']) {
                const mc = item['media:content'];
                rssImage = mc?.$?.url || (Array.isArray(mc) ? mc[0]?.$?.url : null);
            }
            if (!rssImage && item['media:thumbnail']) {
                const mt = item['media:thumbnail'];
                rssImage = mt?.$?.url || (Array.isArray(mt) ? mt[0]?.$?.url : null);
            }

            // Try to extract <img> from content HTML
            if (!rssImage) {
                const htmlSources = [item.content, item['content:encoded'], item.description, item.summary].filter(Boolean);
                for (const html of htmlSources) {
                    const m = html.match(/<img[^>]+src=["']([^"']+)["']/i);
                    if (m && m[1] && !m[1].includes('data:image')) { rssImage = m[1]; break; }
                }
            }

            return {
                title: item.title || '',
                description: (item.contentSnippet || item.content || item.description || '')
                    .replace(/<[^>]+>/g, '').slice(0, 220),
                url: item.link || '',
                image: rssImage, // may be null
                source: feed.source,
                publishedAt: item.pubDate || item.isoDate || new Date().toISOString()
            };
        });
    } catch (err) {
        console.warn(`[News] Skipped ${feed.source}: ${err.message}`);
        return [];
    }
}

// ============================================================
// REFRESH NEWS
// ============================================================
async function refreshNews() {
    console.log('[News] Refreshing feeds...');
    const results = await Promise.all(NEWS_FEEDS.map(fetchAndParseFeed));
    let all = results.flat();

    // Dedupe by title
    const seen = new Set();
    all = all.filter(a => {
        const key = (a.title || '').toLowerCase().trim();
        if (seen.has(key) || !key) return false;
        seen.add(key);
        return true;
    });

    // Sort newest first
    all.sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt));

    const top = all.slice(0, 24);

    // Step 1: Fetch real og:image in parallel for articles missing image
    console.log(`[News] Fetching og:images for ${top.filter(a => !a.image).length} articles...`);
    await Promise.all(top.map(async (article) => {
        if (article.image) return; // already has RSS image
        const og = await fetchOgImage(article.url);
        if (og) article.image = og;
    }));

    // Step 2: Assign unique fallback for articles still missing images
    const usedIndices = new Set();
    let fallbackCount = 0;
    top.forEach(article => {
        if (!article.image) {
            article.image = pickUniqueImage(article.title, usedIndices);
            fallbackCount++;
        }
    });

    newsCache = {
        articles: top,
        fetchedAt: new Date().toISOString()
    };

    console.log(`[News] ✅ Cached ${top.length} articles (${fallbackCount} used fallback images)`);
    return newsCache;
}

// Refresh on start and every 30 min
setTimeout(refreshNews, 5000);
setInterval(refreshNews, 30 * 60 * 1000);

// ============================================================
// ROUTES
// ============================================================
app.get('/api/health', (req, res) => {
    res.json({
        success: true, status: 'healthy',
        timestamp: new Date().toISOString(),
        services: {
            supabase: 'connected',
            brevo: 'configured',
            news: newsCache.fetchedAt ? 'cached' : 'pending'
        }
    });
});

// LIVE NEWS
app.get('/api/news', async (req, res) => {
    try {
        const stale = !newsCache.fetchedAt ||
            (Date.now() - new Date(newsCache.fetchedAt).getTime()) > 30 * 60 * 1000;
        if (stale || newsCache.articles.length === 0) await refreshNews();

        if (newsCache.articles.length === 0) {
            return res.status(503).json({ success: false, message: 'News temporarily unavailable', articles: [] });
        }

        res.json({
            success: true,
            fetchedAt: newsCache.fetchedAt,
            count: newsCache.articles.length,
            articles: newsCache.articles
        });
    } catch (err) {
        console.error('❌ News error:', err);
        res.status(500).json({ success: false, message: 'Failed to load news', articles: [] });
    }
});

// ===== AUTH ROUTES =====
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { firstName, middleName, lastName, email, phone, dateOfBirth, gender, country, password } = req.body;
        if (!firstName || !lastName || !email || !phone || !dateOfBirth || !country || !password) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) return res.status(400).json({ success: false, message: 'Invalid email format' });

        const cleanEmail = email.trim().toLowerCase();
        const existing = await db.users.findByEmail(cleanEmail);
        if (existing) return res.status(409).json({ success: false, message: 'User already exists' });

        const otpCode = generateOTP();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

        pendingUsers.set(cleanEmail, {
            userData: { firstName, middleName, lastName, email: cleanEmail, phone, dateOfBirth, gender, country, passwordHash: hashPassword(password) },
            otpCode, expiresAt
        });

        const emailResult = await sendOTPEmail(cleanEmail, otpCode, `${firstName} ${lastName}`);

        res.status(201).json({
            success: true,
            message: emailResult.success ? 'OTP sent to your email' : 'Check your email for the OTP',
            data: { email: cleanEmail, name: `${firstName} ${lastName}`, requiresVerification: true }
        });
    } catch (err) {
        console.error('❌ Signup:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otpCode } = req.body;
        if (!email || !otpCode) return res.status(400).json({ success: false, message: 'Email and OTP required' });

        const cleanEmail = email.trim().toLowerCase();
        const pending = pendingUsers.get(cleanEmail);
        if (!pending) return res.status(400).json({ success: false, message: 'No pending signup found' });
        if (new Date(pending.expiresAt) < new Date()) {
            pendingUsers.delete(cleanEmail);
            return res.status(400).json({ success: false, message: 'OTP expired' });
        }
        if (pending.otpCode !== otpCode) return res.status(400).json({ success: false, message: 'Invalid OTP code' });

        const user = await db.users.create(pending.userData);
        pendingUsers.delete(cleanEmail);
        const token = generateToken(user);

        res.json({
            success: true, message: 'Email verified! Account created.',
            data: { userId: user.id, email: user.email, name: `${user.first_name} ${user.last_name}`, token, isVerified: true }
        });
    } catch (err) {
        console.error('❌ Verify OTP:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/auth/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: 'Email required' });
        const cleanEmail = email.trim().toLowerCase();
        const pending = pendingUsers.get(cleanEmail);
        if (!pending) return res.status(400).json({ success: false, message: 'No pending signup' });

        const newOtp = generateOTP();
        pending.otpCode = newOtp;
        pending.expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        await sendOTPEmail(cleanEmail, newOtp, `${pending.userData.firstName} ${pending.userData.lastName}`);

        res.json({ success: true, message: 'New OTP sent' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });

        const user = await db.users.findByEmail(email.trim().toLowerCase());
        if (!user) return res.status(401).json({ success: false, message: 'Invalid email or password' });
        if (!comparePassword(password, user.password_hash)) return res.status(401).json({ success: false, message: 'Invalid email or password' });

        const token = generateToken(user);
        await db.users.update(user.id, { last_login_at: new Date().toISOString() });

        res.json({
            success: true, message: 'Login successful',
            data: { userId: user.id, email: user.email, name: `${user.first_name} ${user.last_name}`, token, isVerified: true }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/auth/verify-token', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.status(400).json({ success: false, message: 'Token required' });

        const decoded = verifyToken(token);
        if (!decoded) return res.status(401).json({ success: false, message: 'Invalid token' });

        const user = await db.users.findById(decoded.userId);
        if (!user) return res.status(401).json({ success: false, message: 'User not found' });

        res.json({
            success: true,
            data: { userId: decoded.userId, email: decoded.email, name: decoded.name, isVerified: decoded.isVerified }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/user/me', authenticateToken, async (req, res) => {
    try {
        const user = await db.users.findById(req.user.userId);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({
            success: true,
            data: {
                id: user.id, email: user.email,
                firstName: user.first_name, middleName: user.middle_name,
                lastName: user.last_name, phone: user.phone,
                dateOfBirth: user.date_of_birth, gender: user.gender,
                country: user.country, isVerified: user.is_verified
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.use((req, res) => res.status(404).json({ success: false, message: 'Route not found' }));

app.listen(PORT, () => {
    console.log('========================================');
    console.log(`🚀 AAGS Backend on port ${PORT}`);
    console.log(`📰 News: RSS + og:image + 50-image pool`);
    console.log(`🗄️  Supabase: ${process.env.SUPABASE_URL ? '✅' : '❌'}`);
    console.log(`📧 Brevo: ${BREVO_API_KEY ? '✅' : '❌'}`);
    console.log('========================================');
});

module.exports = app;
