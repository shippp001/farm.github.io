// ============================================================
// server.js - AAGS Backend Server
// Includes: Auth, JWT, Supabase, Brevo (fast OTP), News RSS,
// BTC Payment Cipher, Tracking, Admin, Support Chat, Email
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
const requiredEnvVars = [
    'SUPABASE_URL',
    'SUPABASE_SERVICE_KEY',
    'JWT_SECRET',
    'BREVO_API_KEY',
    'BREVO_FROM_EMAIL'
];

const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
    console.error('❌ Missing env vars:', missingVars.join(', '));
    process.exit(1);
}

// ============================================================
// CONFIGURATION
// ============================================================
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = '7d';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Only-The-Family';

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
);

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_FROM_EMAIL = process.env.BREVO_FROM_EMAIL;
const BREVO_FROM_NAME = process.env.BREVO_FROM_NAME || 'AAGS';

// Brevo client setup (singleton for speed)
const defaultClient = SibApiV3Sdk.ApiClient.instance;
defaultClient.authentications['api-key'].apiKey = BREVO_API_KEY;
const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();

// Speed optimization: set timeout on Brevo requests
try {
    if (defaultClient.timeout !== undefined) defaultClient.timeout = 15000;
} catch (e) {}

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
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use((req, res, next) => {
    console.log(`📝 ${req.method} ${req.path}`);
    next();
});

app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));

// ============================================================
// DATABASE HELPERS
// ============================================================
const db = {
    users: {
        async create(d) {
            const { data, error } = await supabase.from('users').insert([{
                email: d.email,
                password_hash: d.passwordHash,
                first_name: d.firstName,
                middle_name: d.middleName || null,
                last_name: d.lastName,
                phone: d.phone,
                date_of_birth: d.dateOfBirth,
                gender: d.gender || null,
                country: d.country,
                is_verified: true,
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
    },
    applications: {
        async create(payload) {
            const { data, error } = await supabase.from('grant_applications').insert([{
                ref_number: payload.refNumber,
                user_id: payload.userId,
                email: payload.email,
                form_data: payload.formData,
                selections: payload.selections,
                uploaded_files: payload.uploadedFiles,
                status: 'Pending',
                created_at: new Date().toISOString()
            }]).select().single();
            if (error) {
                console.warn('⚠️ Application insert failed:', error.message);
                return null;
            }
            return data;
        }
    }
};

const pendingUsers = new Map();

// ============================================================
// EMAIL SERVICE (Brevo) — FAST VERSION
// ============================================================
// Builds the OTP email HTML
function buildOTPHtml(otpCode, userName) {
    return `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#f7f4f0;border-radius:12px;">
            <div style="background:#fff;padding:30px;border-radius:12px;">
                <h1 style="color:#1a4a3a;text-align:center;font-size:28px;margin:0 0 4px;">AAGS<span style="color:#c6a15b;">.</span></h1>
                <p style="color:#5a6b6b;text-align:center;font-size:12px;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 20px;">American Agricultural Grant Services</p>
                <h2 style="color:#1a4a3a;text-align:center;font-size:22px;margin:0 0 16px;">Verify Your Email</h2>
                <p style="color:#1e2b2b;font-size:15px;">Hello ${userName},</p>
                <p style="color:#1e2b2b;font-size:15px;">Your verification code is:</p>
                <div style="text-align:center;margin:24px 0;">
                    <div style="display:inline-block;background:#f7f2e9;padding:14px 38px;border-radius:8px;font-size:32px;font-weight:700;letter-spacing:8px;color:#1a4a3a;border:2px solid #c6a15b;">
                        ${otpCode}
                    </div>
                </div>
                <p style="color:#5a6b6b;font-size:13px;text-align:center;">This code expires in 15 minutes.</p>
                <p style="color:#5a6b6b;font-size:12px;text-align:center;margin-top:20px;">If you didn't request this, please ignore this email.</p>
            </div>
        </div>
    `;
}

// FIRE-AND-FORGET OTP SEND
// Returns immediately, sends email in background.
// The response to the user does not wait for Brevo.
function sendOTPEmailAsync(email, otpCode, userName) {
    // Validate email synchronously
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        console.warn('⚠️ Invalid email, skipping send:', email);
        return;
    }

    // Fire the send in the background (do NOT await)
    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    sendSmtpEmail.subject = 'Verify Your AAGS Account';
    sendSmtpEmail.htmlContent = buildOTPHtml(otpCode, userName);
    sendSmtpEmail.sender = { name: BREVO_FROM_NAME, email: BREVO_FROM_EMAIL };
    sendSmtpEmail.to = [{ email, name: userName }];

    // Start the request — do not block
    const startTime = Date.now();
    apiInstance.sendTransacEmail(sendSmtpEmail)
        .then(response => {
            const elapsed = Date.now() - startTime;
            console.log(`✅ OTP email sent to ${email} in ${elapsed}ms`);
        })
        .catch(err => {
            const elapsed = Date.now() - startTime;
            console.error(`❌ OTP email failed after ${elapsed}ms:`, err.response?.body || err.message);
        });
}

// Keep the awaited version for places where we need a result
async function sendOTPEmailSync(email, otpCode, userName) {
    try {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) return { success: false, error: 'Invalid email' };

        const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
        sendSmtpEmail.subject = 'Verify Your AAGS Account';
        sendSmtpEmail.htmlContent = buildOTPHtml(otpCode, userName);
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
function requireAdmin(req, res, next) {
    const auth = req.headers['x-admin-key'];
    if (auth !== ADMIN_PASSWORD) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
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
    'https://images.unsplash.com/photo-1516253593875-bd7ba052fbc5?w=600&h=400&fit=crop'
];

function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash;
    }
    return Math.abs(hash);
}
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

const ogImageCache = new Map();
async function fetchOgImage(url, timeout = 6000) {
    if (!url) return null;
    if (ogImageCache.has(url)) return ogImageCache.get(url);
    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);
        const res = await fetch(url, {
            redirect: 'follow',
            signal: controller.signal,
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'Accept': 'text/html' }
        });
        clearTimeout(timer);
        if (!res.ok) { ogImageCache.set(url, null); return null; }
        const html = await res.text();
        const match = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
            || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i)
            || html.match(/<meta[^>]+name=["']twitter:image["'][^>]+content=["']([^"']+)["']/i);
        const image = match ? match[1] : null;
        ogImageCache.set(url, image);
        return image;
    } catch (e) {
        ogImageCache.set(url, null);
        return null;
    }
}

async function fetchAndParseFeed(feed) {
    try {
        const parsed = await rssParser.parseURL(feed.url);
        return (parsed.items || []).slice(0, 8).map(item => {
            let rssImage = null;
            if (item.enclosure?.url) rssImage = item.enclosure.url;
            if (!rssImage && item['media:content']) {
                const mc = item['media:content'];
                rssImage = mc?.$?.url || (Array.isArray(mc) ? mc[0]?.$?.url : null);
            }
            if (!rssImage) {
                const htmlSources = [item.content, item['content:encoded'], item.description].filter(Boolean);
                for (const html of htmlSources) {
                    const m = html.match(/<img[^>]+src=["']([^"']+)["']/i);
                    if (m && m[1] && !m[1].includes('data:image')) { rssImage = m[1]; break; }
                }
            }
            return {
                title: item.title || '',
                description: (item.contentSnippet || item.content || item.description || '').replace(/<[^>]+>/g, '').slice(0, 220),
                url: item.link || '',
                image: rssImage,
                source: feed.source,
                publishedAt: item.pubDate || item.isoDate || new Date().toISOString()
            };
        });
    } catch (err) {
        console.warn(`[News] Skipped ${feed.source}: ${err.message}`);
        return [];
    }
}

async function refreshNews() {
    console.log('[News] Refreshing feeds...');
    const results = await Promise.all(NEWS_FEEDS.map(fetchAndParseFeed));
    let all = results.flat();

    const seen = new Set();
    all = all.filter(a => {
        const key = (a.title || '').toLowerCase().trim();
        if (seen.has(key) || !key) return false;
        seen.add(key);
        return true;
    });
    all.sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt));
    const top = all.slice(0, 24);

    await Promise.all(top.map(async (article) => {
        if (article.image) return;
        const og = await fetchOgImage(article.url);
        if (og) article.image = og;
    }));

    const usedIndices = new Set();
    top.forEach(article => {
        if (!article.image) {
            article.image = pickUniqueImage(article.title, usedIndices);
        }
    });

    newsCache = { articles: top, fetchedAt: new Date().toISOString() };
    console.log(`[News] ✅ Cached ${top.length} articles`);
    return newsCache;
}

setTimeout(refreshNews, 5000);
setInterval(refreshNews, 30 * 60 * 1000);

// ============================================================
// BTC PAYMENT CIPHER
// ============================================================
const BTC_API_BASE = 'https://blockchain.info';
const paymentChecks = new Map();

app.post('/api/payment/verify-btc', async (req, res) => {
    try {
        const { address, expectedAmountUSD, expectedAmountBTC, txid } = req.body;
        if (!address) return res.status(400).json({ success: false, message: 'BTC address required' });

        const cacheKey = address + '|' + (txid || '');
        const cached = paymentChecks.get(cacheKey);
        if (cached && (Date.now() - cached.checkedAt) < 8000) {
            return res.json(cached.data);
        }

        const apiRes = await fetch(`${BTC_API_BASE}/rawaddr/${address}?limit=20`, {
            headers: { 'User-Agent': 'AAGS-Payment-Cipher/1.0' }
        });
        if (!apiRes.ok) throw new Error(`Blockchain.com returned ${apiRes.status}`);
        const data = await apiRes.json();

        const totalReceived = data.total_received || 0;
        const nTx = data.n_tx || 0;
        const finalBalance = data.final_balance || 0;
        const expectedSatoshi = Math.round((parseFloat(expectedAmountBTC) || 0) * 100000000);

        let latestTx = null;
        let confirmations = 0;
        let receivedSatoshi = 0;

        if (data.txs && data.txs.length > 0) {
            const incomingTxs = data.txs
                .filter(tx => tx.out && tx.out.some(o => o.addr === address))
                .sort((a, b) => b.time - a.time);

            if (incomingTxs.length > 0) {
                latestTx = incomingTxs[0];
                receivedSatoshi = latestTx.out
                    .filter(o => o.addr === address)
                    .reduce((sum, o) => sum + (o.value || 0), 0);

                if (latestTx.block_height) {
                    try {
                        const blockRes = await fetch(`${BTC_API_BASE}/latestblock`);
                        const blockData = await blockRes.json();
                        confirmations = (blockData.height - latestTx.block_height) + 1;
                    } catch (e) {}
                }
            }
        }

        let status = 'awaiting';
        if (receivedSatoshi > 0) {
            if (confirmations >= 1) status = 'confirmed';
            else if (confirmations === 0) status = 'pending';
            else status = 'confirming';
        } else if (nTx === 0) {
            status = 'awaiting';
        }

        const result = {
            success: true,
            status,
            address,
            totalReceivedSatoshi: totalReceived,
            totalReceivedBTC: (totalReceived / 100000000).toFixed(8),
            receivedSatoshi,
            receivedBTC: (receivedSatoshi / 100000000).toFixed(8),
            expectedSatoshi,
            expectedBTC: expectedAmountBTC,
            confirmations,
            nTx,
            finalBalanceSatoshi: finalBalance,
            finalBalanceBTC: (finalBalance / 100000000).toFixed(8),
            latestTxHash: latestTx ? latestTx.hash : null,
            latestTxTime: latestTx ? latestTx.time : null,
            checkedAt: new Date().toISOString()
        };

        paymentChecks.set(cacheKey, { checkedAt: Date.now(), data: result });
        if (paymentChecks.size > 200) {
            const oldestKey = paymentChecks.keys().next().value;
            paymentChecks.delete(oldestKey);
        }

        res.json(result);
    } catch (err) {
        console.error('❌ Cipher error:', err.message);
        res.status(500).json({
            success: false,
            status: 'error',
            message: 'Unable to verify payment at this time.'
        });
    }
});

// ============================================================
// HEALTH
// ============================================================
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        services: {
            supabase: 'connected',
            brevo: 'configured',
            news: newsCache.fetchedAt ? 'cached' : 'pending',
            cipher: 'active',
            tracking: 'active',
            admin: 'active',
            support: 'active'
        }
    });
});

// ============================================================
// NEWS
// ============================================================
app.get('/api/news', async (req, res) => {
    try {
        const stale = !newsCache.fetchedAt ||
            (Date.now() - new Date(newsCache.fetchedAt).getTime()) > 30 * 60 * 1000;
        if (stale || newsCache.articles.length === 0) await refreshNews();

        if (newsCache.articles.length === 0) {
            return res.status(503).json({ success: false, message: 'News unavailable', articles: [] });
        }
        res.json({
            success: true,
            fetchedAt: newsCache.fetchedAt,
            count: newsCache.articles.length,
            articles: newsCache.articles
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to load news', articles: [] });
    }
});

// ============================================================
// AUTH — FAST OTP
// ============================================================

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { firstName, middleName, lastName, email, phone, dateOfBirth, gender, country, password } = req.body;

        if (!firstName || !lastName || !email || !phone || !dateOfBirth || !country || !password) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email format' });
        }

        const cleanEmail = email.trim().toLowerCase();
        const existing = await db.users.findByEmail(cleanEmail);
        if (existing) {
            return res.status(409).json({ success: false, message: 'User already exists' });
        }

        const otpCode = generateOTP();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

        pendingUsers.set(cleanEmail, {
            userData: {
                firstName, middleName, lastName,
                email: cleanEmail, phone, dateOfBirth, gender, country,
                passwordHash: hashPassword(password)
            },
            otpCode, expiresAt
        });

        // ⚡ FIRE AND FORGET — response goes back immediately
        sendOTPEmailAsync(cleanEmail, otpCode, `${firstName} ${lastName}`);

        // Respond IMMEDIATELY (don't wait for email)
        res.status(201).json({
            success: true,
            message: 'OTP is being sent to your email',
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
        if (pending.otpCode !== otpCode) {
            return res.status(400).json({ success: false, message: 'Invalid OTP code' });
        }

        const user = await db.users.create(pending.userData);
        pendingUsers.delete(cleanEmail);
        const token = generateToken(user);

        res.json({
            success: true,
            message: 'Email verified! Account created.',
            data: {
                userId: user.id, email: user.email,
                name: `${user.first_name} ${user.last_name}`,
                token, isVerified: true
            }
        });
    } catch (err) {
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

        // ⚡ FIRE AND FORGET
        sendOTPEmailAsync(cleanEmail, newOtp, `${pending.userData.firstName} ${pending.userData.lastName}`);

        res.json({ success: true, message: 'New OTP is being sent' });
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
        if (!comparePassword(password, user.password_hash)) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }

        const token = generateToken(user);
        await db.users.update(user.id, { last_login_at: new Date().toISOString() });

        res.json({
            success: true,
            message: 'Login successful',
            data: {
                userId: user.id, email: user.email,
                name: `${user.first_name} ${user.last_name}`,
                token, isVerified: true
            }
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

// ============================================================
// GRANT APPLICATION
// ============================================================
app.post('/api/grants/apply', async (req, res) => {
    try {
        const { refNumber, userId, email, formData, selections, uploadedFiles } = req.body;
        const result = await db.applications.create({
            refNumber, userId, email, formData, selections, uploadedFiles
        });
        res.json({
            success: true,
            message: 'Application submitted successfully',
            data: result || { refNumber }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ============================================================
// TRACKING
// ============================================================

app.post('/api/track/visit', async (req, res) => {
    try {
        const { session_id, source_key, page, referrer, user_agent, email, full_name } = req.body;
        if (!session_id) return res.status(400).json({ success: false });

        // Fire insert in background, respond immediately
        supabase.from('visits').insert([{
            session_id,
            source_key: source_key || 'unknown',
            page: page || 'unknown',
            referrer: referrer || null,
            user_agent: user_agent || null,
            email: email || null
        }]).catch(() => {});

        // Journey upsert (this one needs to complete for accurate data, but fast)
        const { data: existing } = await supabase
            .from('user_journey')
            .select('id, current_step, email, full_name, source_key')
            .eq('session_id', session_id)
            .maybeSingle();

        if (!existing) {
            await supabase.from('user_journey').insert([{
                session_id,
                source_key: source_key || 'unknown',
                email: email || null,
                full_name: full_name || null,
                current_step: 'visitor',
                last_page: page,
                first_seen_at: new Date().toISOString(),
                last_seen_at: new Date().toISOString()
            }]);
        } else {
            const updates = {
                last_seen_at: new Date().toISOString(),
                last_page: page
            };
            if (email && !existing.email) updates.email = email;
            if (full_name && !existing.full_name) updates.full_name = full_name;
            if (source_key && existing.source_key === 'unknown') updates.source_key = source_key;

            await supabase.from('user_journey').update(updates).eq('id', existing.id);
        }

        res.json({ success: true });
    } catch (err) {
        console.error('❌ Track visit:', err.message);
        res.status(500).json({ success: false });
    }
});

app.post('/api/track/click', async (req, res) => {
    try {
        const { session_id, source_key, event_type, event_label, page, metadata, email, full_name } = req.body;
        if (!session_id || !event_type) return res.status(400).json({ success: false });

        // Fire click insert in background
        supabase.from('clicks').insert([{
            session_id,
            source_key: source_key || 'unknown',
            event_type,
            event_label: event_label || event_type,
            page: page || null,
            metadata: metadata || {},
            email: email || null
        }]).catch(() => {});

        const stepMap = {
            'click_signup': 'signup_started',
            'signup_complete': 'otp_pending',
            'otp_verified': 'registered',
            'click_download_form': 'grant_downloaded',
            'download_form': 'grant_downloaded',
            'upload_form_complete': 'form_uploaded',
            'face_verified': 'face_verified',
            'click_proceed_payment': 'payment_started',
            'payment_started': 'payment_started',
            'payment_completed': 'payment_completed'
        };

        const flagMap = {
            'signup_complete': 'signup_completed',
            'otp_verified': 'otp_verified',
            'download_form': 'grant_form_downloaded',
            'upload_form_complete': 'form_uploaded',
            'face_verified': 'face_verified',
            'payment_started': 'payment_started',
            'payment_completed': 'payment_completed'
        };

        const { data: existing } = await supabase
            .from('user_journey')
            .select('*')
            .eq('session_id', session_id)
            .maybeSingle();

        if (existing) {
            const updates = { last_seen_at: new Date().toISOString() };

            if (stepMap[event_type]) {
                const stepOrder = ['visitor', 'signup_started', 'otp_pending', 'registered',
                    'grant_downloaded', 'form_uploaded', 'face_verified',
                    'payment_started', 'payment_completed'];
                const currentIdx = stepOrder.indexOf(existing.current_step || 'visitor');
                const newIdx = stepOrder.indexOf(stepMap[event_type]);
                if (newIdx > currentIdx) updates.current_step = stepMap[event_type];
            }

            Object.entries(flagMap).forEach(([key, flag]) => {
                if (event_type === key) updates[flag] = true;
            });

            if (email && !existing.email) updates.email = email;
            if (full_name && !existing.full_name) updates.full_name = full_name;

            await supabase.from('user_journey').update(updates).eq('id', existing.id);
        }

        res.json({ success: true });
    } catch (err) {
        console.error('❌ Track click:', err.message);
        res.status(500).json({ success: false });
    }
});

// ============================================================
// SUPPORT CHAT
// ============================================================

app.post('/api/support/start', async (req, res) => {
    try {
        const { session_id, user_email, user_name, source_key, subject } = req.body;
        if (!session_id) return res.status(400).json({ success: false, message: 'session_id required' });

        const { data: existing } = await supabase
            .from('support_conversations')
            .select('*')
            .eq('session_id', session_id)
            .eq('status', 'open')
            .order('created_at', { ascending: false })
            .limit(1)
            .maybeSingle();

        if (existing) {
            return res.json({ success: true, data: existing, resumed: true });
        }

        const { data, error } = await supabase
            .from('support_conversations')
            .insert([{
                session_id,
                user_email: user_email || null,
                user_name: user_name || 'Guest',
                source_key: source_key || 'unknown',
                subject: subject || 'Support Request'
            }])
            .select()
            .single();

        if (error) throw error;

        await supabase.from('support_messages').insert([{
            conversation_id: data.id,
            sender: 'system',
            sender_name: 'AAGS Support',
            body: '👋 Welcome to AAGS Support! A team member will be with you shortly. Feel free to describe your issue below.',
            read_by_user: false,
            read_by_admin: true
        }]);

        res.json({ success: true, data, resumed: false });
    } catch (err) {
        console.error('❌ Support start:', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/support/message', async (req, res) => {
    try {
        const { conversation_id, sender, sender_name, body } = req.body;
        if (!conversation_id || !body || !sender) {
            return res.status(400).json({ success: false, message: 'Missing fields' });
        }

        const { data: msg, error } = await supabase
            .from('support_messages')
            .insert([{
                conversation_id,
                sender,
                sender_name: sender_name || (sender === 'admin' ? 'AAGS Support' : 'User'),
                body,
                read_by_user: sender === 'user',
                read_by_admin: sender === 'admin'
            }])
            .select()
            .single();

        if (error) throw error;

        const { data: conv } = await supabase
            .from('support_conversations')
            .select('unread_by_admin, unread_by_user')
            .eq('id', conversation_id)
            .single();

        if (conv) {
            const updates = { last_message_at: new Date().toISOString() };
            if (sender === 'user') updates.unread_by_admin = (conv.unread_by_admin || 0) + 1;
            else updates.unread_by_user = (conv.unread_by_user || 0) + 1;
            await supabase.from('support_conversations').update(updates).eq('id', conversation_id);
        }

        res.json({ success: true, data: msg });
    } catch (err) {
        console.error('❌ Support message:', err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/support/messages/:conversationId', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('support_messages')
            .select('*')
            .eq('conversation_id', req.params.conversationId)
            .order('created_at', { ascending: true });

        if (error) throw error;
        res.json({ success: true, data: data || [] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/support/read', async (req, res) => {
    try {
        const { conversation_id, reader } = req.body;

        if (reader === 'admin') {
            await supabase.from('support_messages')
                .update({ read_by_admin: true })
                .eq('conversation_id', conversation_id)
                .eq('read_by_admin', false);
            await supabase.from('support_conversations')
                .update({ unread_by_admin: 0 }).eq('id', conversation_id);
        } else {
            await supabase.from('support_messages')
                .update({ read_by_user: true })
                .eq('conversation_id', conversation_id)
                .eq('read_by_user', false);
            await supabase.from('support_conversations')
                .update({ unread_by_user: 0 }).eq('id', conversation_id);
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ============================================================
// ADMIN
// ============================================================

app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        res.json({ success: true, message: 'Authenticated' });
    } else {
        res.status(401).json({ success: false, message: 'Invalid password' });
    }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const { data: users, error } = await supabase
            .from('users').select('*').order('created_at', { ascending: false });
        if (error) throw error;

        const { data: journeys } = await supabase.from('user_journey').select('*');

        const merged = (users || []).map(u => {
            const j = (journeys || []).find(x => x.email === u.email) || {};
            return { ...u, journey: j };
        });

        res.json({ success: true, data: merged });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/journeys', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('user_journey').select('*')
            .order('last_seen_at', { ascending: false })
            .limit(500);
        if (error) throw error;
        res.json({ success: true, data: data || [] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/clicks', requireAdmin, async (req, res) => {
    try {
        const { source, limit = 200 } = req.query;
        let q = supabase.from('clicks').select('*')
            .order('created_at', { ascending: false })
            .limit(parseInt(limit));
        if (source) q = q.eq('source_key', source);
        const { data, error } = await q;
        if (error) throw error;
        res.json({ success: true, data: data || [] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/visits', requireAdmin, async (req, res) => {
    try {
        const { source, limit = 200 } = req.query;
        let q = supabase.from('visits').select('*')
            .order('created_at', { ascending: false })
            .limit(parseInt(limit));
        if (source) q = q.eq('source_key', source);
        const { data, error } = await q;
        if (error) throw error;
        res.json({ success: true, data: data || [] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try {
        const sources = ['quavo', 'zhus', 'iszo', 'unknown'];
        const result = {};

        await Promise.all(sources.map(async (src) => {
            const [v, c, u, p] = await Promise.all([
                supabase.from('visits').select('*', { count: 'exact', head: true }).eq('source_key', src),
                supabase.from('clicks').select('*', { count: 'exact', head: true }).eq('source_key', src),
                supabase.from('user_journey').select('*', { count: 'exact', head: true }).eq('source_key', src),
                supabase.from('user_journey').select('*', { count: 'exact', head: true }).eq('source_key', src).eq('payment_completed', true)
            ]);

            result[src] = {
                visits: v.count || 0,
                clicks: c.count || 0,
                users: u.count || 0,
                payments: p.count || 0
            };
        }));

        res.json({ success: true, data: result });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/admin/conversations', requireAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('support_conversations')
            .select('*')
            .order('last_message_at', { ascending: false })
            .limit(200);

        if (error) throw error;

        const convs = data || [];
        await Promise.all(convs.map(async (c) => {
            const { data: last } = await supabase
                .from('support_messages')
                .select('body, sender, created_at')
                .eq('conversation_id', c.id)
                .order('created_at', { ascending: false })
                .limit(1)
                .maybeSingle();
            c.last_message = last || null;
        }));

        res.json({ success: true, data: convs });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Admin email send
app.post('/api/admin/email/send', requireAdmin, async (req, res) => {
    try {
        const { to, toName, subject, body, replyTo } = req.body;

        if (!to || !subject || !body) {
            return res.status(400).json({ success: false, message: 'Missing fields' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(to)) {
            return res.status(400).json({ success: false, message: 'Invalid email' });
        }

        const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
        sendSmtpEmail.subject = subject;
        sendSmtpEmail.htmlContent = body;
        sendSmtpEmail.sender = { name: BREVO_FROM_NAME, email: BREVO_FROM_EMAIL };
        sendSmtpEmail.to = [{ email: to, name: toName || to }];
        if (replyTo) sendSmtpEmail.replyTo = { email: replyTo };

        const response = await apiInstance.sendTransacEmail(sendSmtpEmail);

        await supabase.from('email_log').insert([{
            to_email: to,
            to_name: toName || null,
            subject,
            body,
            status: 'sent',
            message_id: response.messageId || null,
            sent_by: 'admin'
        }]);

        console.log(`✅ Admin email sent to ${to}`);
        res.json({ success: true, messageId: response.messageId });
    } catch (err) {
        console.error('❌ Admin email error:', err.response?.body || err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ============================================================
// 404
// ============================================================
app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Route not found' });
});

// ============================================================
// START
// ============================================================
app.listen(PORT, () => {
    console.log('========================================');
    console.log(`🚀 AAGS Backend on port ${PORT}`);
    console.log(`🔐 JWT: ${JWT_SECRET ? '✅' : '❌'}`);
    console.log(`🗄️  Supabase: ${process.env.SUPABASE_URL ? '✅' : '❌'}`);
    console.log(`📧 Brevo: ${BREVO_API_KEY ? '✅' : '❌'} (async mode enabled)`);
    console.log(`📰 News: ✅`);
    console.log(`🔎 BTC Cipher: ✅`);
    console.log(`📊 Tracking: ✅`);
    console.log(`💬 Support Chat: ✅`);
    console.log(`📨 Admin Email: ✅`);
    console.log(`🔐 Admin: ✅`);
    console.log('========================================');
});

module.exports = app;
