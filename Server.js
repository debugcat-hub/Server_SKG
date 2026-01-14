const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const Razorpay = require("razorpay");
const path = require("path");
const helmet = require("helmet");
const cors = require("cors");

const app = express();

/* =========================
   SECURITY CONFIGURATION
   ========================= */

// Validate required environment variables
const requiredEnvVars = [
    'RAZORPAY_WEBHOOK_SECRET',
    'RAZORPAY_KEY_ID',
    'RAZORPAY_KEY_SECRET',
    'ANDROID_API_KEY'
];

for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`❌ CRITICAL: Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
}

if (!process.env.ADMIN_TOKEN) {
    console.warn('⚠️  WARNING: ADMIN_TOKEN not set - admin endpoints will be disabled');
}

if (process.env.RAZORPAY_WEBHOOK_SECRET.length < 20) {
    console.error('❌ CRITICAL: RAZORPAY_WEBHOOK_SECRET must be at least 20 characters');
    process.exit(1);
}

if (process.env.ANDROID_API_KEY.length < 32) {
    console.error('❌ CRITICAL: ANDROID_API_KEY must be at least 32 characters');
    process.exit(1);
}

/* =========================
   CONFIG - ALL FROM ENV
   ========================= */
const PORT = process.env.PORT || 5000;
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const ANDROID_API_KEY = process.env.ANDROID_API_KEY;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const NODE_ENV = process.env.NODE_ENV || 'development';

/* =========================
   INITIALIZE RAZORPAY
   ========================= */
const razorpay = new Razorpay({
    key_id: RAZORPAY_KEY_ID,
    key_secret: RAZORPAY_KEY_SECRET
});

/* =========================
   SECURITY MIDDLEWARE
   ========================= */

// Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "checkout.razorpay.com", "cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "api.razorpay.com"],
            frameSrc: ["'self'", "api.razorpay.com"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Simple CORS - Allow all origins for public endpoints, Android app needs access
app.use(cors({
    origin: true, // Allow all origins
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-api-key', 'authorization', 'x-android-key', 'x-admin-token']
}));

// Force HTTPS in production
if (NODE_ENV === 'production') {
    app.use((req, res, next) => {
        if (req.header('x-forwarded-proto') !== 'https') {
            return res.redirect(`https://${req.header('host')}${req.url}`);
        }
        next();
    });
}

/* =========================
   RATE LIMITING
   ========================= */
const webhookLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Too many webhook requests" },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false
});

const androidApiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { error: "Too many API requests" },
    standardHeaders: true,
    legacyHeaders: false,
});

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    message: { error: "Too many requests" },
    standardHeaders: true,
    legacyHeaders: false,
});

const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: { error: "Too many requests from this IP" },
});

/* =========================
   STORAGE
   ========================= */
const pendingTokens = new Map();
const paidBills = new Map();

/* =========================
   INPUT VALIDATION & SANITIZATION
   ========================= */

function sanitizeTokenNumber(token) {
    return String(token).replace(/[^a-zA-Z0-9]/g, '').substring(0, 20);
}

function validateAmount(amount) {
    const num = parseFloat(amount);
    if (isNaN(num) || num <= 0 || num > 1000000) {
        throw new Error('Invalid amount');
    }
    return num;
}

function validateItems(items) {
    if (!Array.isArray(items)) return [];
    return items.slice(0, 100).map(item =>
        String(item).substring(0, 50)
    );
}

/* =========================
   SECURITY LOGGING
   ========================= */

function logSecurityEvent(event, details) {
    const timestamp = new Date().toISOString();
    console.log(`🔒 [SECURITY] ${timestamp} - ${event}:`, JSON.stringify(details));
}

/* =========================
   MIDDLEWARE - CRITICAL ORDER!
   ========================= */
app.set('trust proxy', 1);

// Request size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Static files - NO CACHE for HTML to prevent caching issues
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: 0, // Disable caching
    etag: false,
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
    }
}));

// WEBHOOK ROUTE
app.post(
    "/razorpay-webhook",
    webhookLimiter,
    express.raw({ type: "application/json", limit: '10kb' }),
    (req, res) => {
        const timestamp = new Date().toISOString();
        console.log("📨 Webhook received at:", timestamp);

        const receivedSignature = req.headers["x-razorpay-signature"];

        if (!receivedSignature) {
            logSecurityEvent('WEBHOOK_NO_SIGNATURE', { ip: req.ip });
            return res.status(400).send("Missing signature");
        }

        try {
            const rawBody = req.body.toString('utf8');

            const expectedSignature = crypto
                .createHmac("sha256", RAZORPAY_WEBHOOK_SECRET)
                .update(rawBody)
                .digest("hex");

            if (receivedSignature !== expectedSignature) {
                logSecurityEvent('WEBHOOK_INVALID_SIGNATURE', {
                    ip: req.ip,
                    received: receivedSignature.substring(0, 10) + '...'
                });
                return res.status(400).send("Invalid signature");
            }

            console.log("✅ Signature verified successfully!");

            const payload = JSON.parse(rawBody);
            console.log("📋 Event:", payload.event);

            if (payload.event !== "payment.captured") {
                console.log(`ℹ️ Ignoring event: ${payload.event}`);
                return res.status(200).send("OK");
            }

            const payment = payload.payload.payment.entity;
            const tokenNumber = sanitizeTokenNumber(payment.notes?.token_number || 'Unknown');

            console.log(`💰 Payment: ${payment.id} | Token: ${tokenNumber} | ₹${payment.amount / 100}`);

            if (paidBills.has(payment.id)) {
                console.log("⚠️ Duplicate payment");
                return res.status(200).send("Duplicate");
            }

            const tokenData = pendingTokens.get(tokenNumber);

            paidBills.set(payment.id, {
                orderId: payment.order_id,
                paymentId: payment.id,
                tokenNumber: tokenNumber,
                amount: payment.amount / 100,
                items: tokenData?.items || [],
                method: payment.method?.toUpperCase() || 'ONLINE',
                customerName: (payment.notes?.customer_name || payment.email?.split('@')[0] || 'Guest').substring(0, 100),
                customerEmail: (payment.email || '').substring(0, 100),
                customerPhone: (payment.contact || '').substring(0, 20),
                time: new Date().toLocaleTimeString('en-IN', {
                    timeZone: 'Asia/Kolkata',
                    hour12: false
                }),
                date: new Date().toLocaleDateString('en-IN', {
                    timeZone: 'Asia/Kolkata'
                }),
                timestamp: Date.now(),
                printed: false,
                printAttempts: 0
            });

            if (tokenData) {
                tokenData.status = 'paid';
                tokenData.paymentId = payment.id;
                tokenData.paidAt = new Date();
                console.log(`✅ Token ${tokenNumber} marked as PAID`);
            }

            const unprintedCount = Array.from(paidBills.values()).filter(b => !b.printed).length;
            console.log(`✅ Bill stored! Unprinted: ${unprintedCount}`);

            res.status(200).json({ success: true });

        } catch (err) {
            logSecurityEvent('WEBHOOK_ERROR', { error: err.message, ip: req.ip });
            console.error("❌ Webhook error:", err.message);
            res.status(400).send("Error");
        }
    }
);

/* =========================
   AUTHENTICATION MIDDLEWARE
   ========================= */

function authenticateAndroid(req, res, next) {
    const authToken = req.headers['x-api-key'] ||
        req.headers['authorization'] ||
        req.headers['x-android-key'];

    const token = authToken?.replace(/^Bearer\s+/i, '');

    if (!token || token !== ANDROID_API_KEY) {
        logSecurityEvent('AUTH_FAILED_ANDROID', {
            ip: req.ip,
            path: req.path,
            providedKey: token ? token.substring(0, 8) + '...' : 'none'
        });
        return res.status(403).json({
            error: "Forbidden",
            code: "INVALID_API_KEY"
        });
    }

    next();
}

function authenticateAdmin(req, res, next) {
    if (!ADMIN_TOKEN) {
        return res.status(503).json({
            error: "Admin access not configured",
            message: "Set ADMIN_TOKEN environment variable to enable admin endpoints"
        });
    }

    const adminToken = req.headers['x-admin-token'];

    if (!adminToken || adminToken !== ADMIN_TOKEN) {
        logSecurityEvent('AUTH_FAILED_ADMIN', {
            ip: req.ip,
            path: req.path
        });
        return res.status(401).json({ error: "Unauthorized" });
    }

    next();
}

/* =========================
   ALL OTHER ROUTES
   ========================= */

// Android app creates tokens
app.post("/api/create-token", androidApiLimiter, authenticateAndroid, (req, res) => {
    try {
        const { token_number, amount, items } = req.body;

        if (!token_number || !amount) {
            return res.status(400).json({
                error: "Missing required fields",
                required: ["token_number", "amount"]
            });
        }

        const sanitizedToken = sanitizeTokenNumber(token_number);
        const validatedAmount = validateAmount(amount);
        const validatedItems = validateItems(items);

        pendingTokens.set(sanitizedToken, {
            tokenNumber: sanitizedToken,
            amount: validatedAmount,
            items: validatedItems,
            createdAt: Date.now(),
            status: 'pending'
        });

        console.log(`✅ Token created: ${sanitizedToken} | Amount: ₹${validatedAmount}`);

        res.json({
            success: true,
            token_number: sanitizedToken,
            amount: validatedAmount,
            message: "Token created successfully"
        });

    } catch (err) {
        console.error("Create token error:", err.message);
        res.status(500).json({ error: "Failed to create token" });
    }
});

// PUBLIC - Payment page fetches pending tokens
app.get("/api/pending-tokens", (req, res) => {
    const twentyFourHours = 24 * 60 * 60 * 1000;
    for (const [tokenNumber, token] of pendingTokens.entries()) {
        if (Date.now() - token.createdAt > twentyFourHours) {
            pendingTokens.delete(tokenNumber);
        }
    }

    const tokens = Array.from(pendingTokens.values())
        .filter(t => t.status === 'pending')
        .map(t => ({
            token_number: t.tokenNumber,
            amount: t.amount,
            items: t.items
        }));

    res.json({ tokens });
});

// PUBLIC - Payment page creates order for Razorpay
app.post("/api/create-order", strictLimiter, async (req, res) => {
    try {
        const { token_number } = req.body;

        if (!token_number) {
            return res.status(400).json({ error: "Missing token_number" });
        }

        const sanitizedToken = sanitizeTokenNumber(token_number);
        const token = pendingTokens.get(sanitizedToken);

        if (!token) {
            return res.status(404).json({ error: "Token not found" });
        }

        if (token.status !== 'pending') {
            return res.status(400).json({ error: "Token already paid" });
        }

        const order = await razorpay.orders.create({
            amount: Math.round(token.amount * 100),
            currency: 'INR',
            receipt: `token_${sanitizedToken}_${Date.now()}`,
            notes: {
                token_number: sanitizedToken
            }
        });

        console.log(`📝 Order created: ${order.id} for Token: ${sanitizedToken}`);

        res.json({
            success: true,
            order_id: order.id,
            amount: order.amount,
            currency: order.currency,
            key: RAZORPAY_KEY_ID,
            token_number: sanitizedToken
        });

    } catch (err) {
        console.error("Order creation error:", err.message);
        res.status(500).json({ error: "Failed to create order" });
    }
});

// Android app polls for bills to print
app.get("/api/latest-paid-bill", androidApiLimiter, authenticateAndroid, (req, res) => {
    const twoHoursAgo = Date.now() - (2 * 60 * 60 * 1000);
    for (const [paymentId, bill] of paidBills.entries()) {
        if (bill.timestamp && bill.timestamp < twoHoursAgo) {
            paidBills.delete(paymentId);
        }
    }

    const unprintedBills = Array.from(paidBills.values())
        .filter(b => !b.printed)
        .sort((a, b) => a.timestamp - b.timestamp);

    if (unprintedBills.length > 0) {
        const bill = unprintedBills[0];
        bill.printAttempts = (bill.printAttempts || 0) + 1;
        bill.lastPrintAttempt = Date.now();

        return res.json({
            orderId: bill.orderId,
            paymentId: bill.paymentId,
            tokenNumber: bill.tokenNumber,
            amount: bill.amount,
            items: bill.items,
            method: bill.method,
            customerName: bill.customerName,
            customerEmail: bill.customerEmail,
            customerPhone: bill.customerPhone,
            time: bill.time,
            date: bill.date,
            timestamp: bill.timestamp,
            printed: bill.printed,
            serverTime: new Date().toISOString(),
            serverTimestamp: Date.now()
        });
    }

    res.status(204).send();
});

// Android app confirms print
app.post("/api/confirm-print", androidApiLimiter, authenticateAndroid, (req, res) => {
    try {
        const { paymentId } = req.body;

        if (!paymentId) {
            return res.status(400).json({ error: "Missing paymentId" });
        }

        const bill = paidBills.get(paymentId);
        if (bill) {
            bill.printed = true;
            bill.printConfirmedAt = Date.now();

            const unprintedCount = Array.from(paidBills.values()).filter(b => !b.printed).length;

            console.log(`✅ Print confirmed: ${paymentId} (Token: ${bill.tokenNumber})`);

            res.json({
                success: true,
                message: "Print confirmed",
                unprintedBills: unprintedCount
            });
        } else {
            res.status(404).json({ error: "Bill not found" });
        }

    } catch (err) {
        console.error("Confirm print error:", err.message);
        res.status(500).json({ error: "Failed to confirm print" });
    }
});

// Serve payment page
app.get("/payment", (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'payment.html'));
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'payment.html'));
});

app.get("/health", globalLimiter, (req, res) => {
    res.json({
        status: "OK",
        uptime: process.uptime(),
        environment: NODE_ENV,
        timestamp: new Date().toISOString(),
        pendingTokens: pendingTokens.size,
        unprintedBills: Array.from(paidBills.values()).filter(b => !b.printed).length
    });
});

// Admin endpoints
app.get("/admin/bills", authenticateAdmin, (req, res) => {
    const pending = Array.from(pendingTokens.values());
    const paid = Array.from(paidBills.values());

    res.json({
        pendingTokens: pending,
        paidBills: paid,
        totalPending: pending.length,
        totalUnprinted: paid.filter(b => !b.printed).length
    });
});

// Debug endpoints - ONLY in development
if (NODE_ENV === 'development') {
    app.get("/debug/bills", (req, res) => {
        const allBills = Array.from(paidBills.entries()).map(([paymentId, bill]) => ({
            paymentId,
            tokenNumber: bill.tokenNumber,
            amount: bill.amount,
            printed: bill.printed,
            printAttempts: bill.printAttempts || 0,
            timestamp: new Date(bill.timestamp).toLocaleString('en-IN')
        }));

        res.json({
            totalBills: paidBills.size,
            unprintedBills: allBills.filter(b => !b.printed).length,
            bills: allBills
        });
    });

    app.get("/test/create-fake-bill", (req, res) => {
        const fakePaymentId = "pay_test_" + Date.now();
        const fakeTokenNumber = sanitizeTokenNumber(req.query.token) || String(Math.floor(1000 + Math.random() * 9000));
        const fakeAmount = validateAmount(req.query.amount || 100);

        paidBills.set(fakePaymentId, {
            orderId: "order_test_" + Date.now(),
            paymentId: fakePaymentId,
            tokenNumber: fakeTokenNumber,
            amount: fakeAmount,
            items: ["₹50", "₹50"],
            method: 'TEST',
            customerName: 'Test Customer',
            customerEmail: 'test@test.com',
            customerPhone: '9999999999',
            time: new Date().toLocaleTimeString('en-IN', {
                timeZone: 'Asia/Kolkata',
                hour12: false
            }),
            date: new Date().toLocaleDateString('en-IN', {
                timeZone: 'Asia/Kolkata'
            }),
            timestamp: Date.now(),
            printed: false,
            printAttempts: 0
        });

        console.log(`🧪 TEST: Created fake bill - Token: ${fakeTokenNumber}, Amount: ₹${fakeAmount}`);

        res.json({
            success: true,
            paymentId: fakePaymentId,
            tokenNumber: fakeTokenNumber,
            amount: fakeAmount,
            message: "Fake bill created"
        });
    });
}

// 404 handler
app.use((req, res) => {
    logSecurityEvent('404_NOT_FOUND', {
        ip: req.ip,
        path: req.path,
        method: req.method
    });
    res.status(404).json({ error: "Not found" });
});

// Error handler
app.use((err, req, res, next) => {
    logSecurityEvent('SERVER_ERROR', {
        error: err.message,
        ip: req.ip,
        path: req.path
    });
    console.error('Server error:', err);
    res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔒 Environment: ${NODE_ENV}`);
    console.log(`✅ Security features enabled`);
    console.log(`📱 Payment URL: https://server-skg.onrender.com/payment`);
    console.log(`🔑 API Key: ${ANDROID_API_KEY ? '✓ Configured' : '✗ Missing'}`);
    console.log(`📝 Webhook Secret: ${RAZORPAY_WEBHOOK_SECRET ? '✓ Configured' : '✗ Missing'}`);
    console.log(`💳 Razorpay: ${RAZORPAY_KEY_ID ? '✓ Configured' : '✗ Missing'}`);

    if (NODE_ENV === 'development') {
        console.log(`🧪 Debug endpoints enabled (dev mode)`);
    }
});
