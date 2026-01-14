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
    // 'ANDROID_API_KEY'  // COMMENTED OUT - Not needed for demo
];

for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`❌ CRITICAL: Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
}

// if (!process.env.ADMIN_TOKEN) {
//     console.warn('⚠️  WARNING: ADMIN_TOKEN not set - admin endpoints will be disabled');
// }

if (process.env.RAZORPAY_WEBHOOK_SECRET.length < 20) {
    console.error('❌ CRITICAL: RAZORPAY_WEBHOOK_SECRET must be at least 20 characters');
    process.exit(1);
}

// COMMENTED OUT - Android API key validation
// if (process.env.ANDROID_API_KEY.length < 32) {
//     console.error('❌ CRITICAL: ANDROID_API_KEY must be at least 32 characters');
//     process.exit(1);
// }

/* =========================
   CONFIG - ALL FROM ENV
   ========================= */
const PORT = process.env.PORT || 5000;
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
// const ANDROID_API_KEY = process.env.ANDROID_API_KEY;  // COMMENTED OUT
// const ADMIN_TOKEN = process.env.ADMIN_TOKEN;  // COMMENTED OUT
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
            scriptSrc: ["'self'", "'unsafe-inline'","checkout.razorpay.com", "cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
            fontSrc: ["'self'", "fonts.gstatic.com"],
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

// Simple CORS - Allow all origins
app.use(cors({
    origin: true,
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

const publicApiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { error: "Too many requests" },
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
const completedOrders = new Map();

/* =========================
   INPUT VALIDATION & SANITIZATION
   ========================= */

function validateAmount(amount) {
    const num = parseFloat(amount);
    if (isNaN(num) || num <= 0 || num > 1000000) {
        throw new Error('Invalid amount');
    }
    return num;
}

function sanitizeItemName(name) {
    return String(name).substring(0, 100);
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

// Static files - NO CACHE for HTML
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: 0,
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
            const itemName = payment.notes?.item_name || 'Unknown Item';

            console.log(`💰 Payment: ${payment.id} | Item: ${itemName} | ₹${payment.amount / 100}`);

            if (completedOrders.has(payment.id)) {
                console.log("⚠️ Duplicate payment");
                return res.status(200).send("Duplicate");
            }

            completedOrders.set(payment.id, {
                orderId: payment.order_id,
                paymentId: payment.id,
                itemName: itemName,
                amount: payment.amount / 100,
                method: payment.method?.toUpperCase() || 'ONLINE',
                customerEmail: (payment.email || '').substring(0, 100),
                customerPhone: (payment.contact || '').substring(0, 20),
                time: new Date().toLocaleTimeString('en-IN', {
                    timeZone: 'Asia/Kolkata',
                    hour12: false
                }),
                date: new Date().toLocaleDateString('en-IN', {
                    timeZone: 'Asia/Kolkata'
                }),
                timestamp: Date.now()
            });

            console.log(`✅ Order stored! Total orders: ${completedOrders.size}`);

            res.status(200).json({ success: true });

        } catch (err) {
            logSecurityEvent('WEBHOOK_ERROR', { error: err.message, ip: req.ip });
            console.error("❌ Webhook error:", err.message);
            res.status(400).send("Error");
        }
    }
);

/* =========================
   PUBLIC ROUTES - FOR FOOD ORDERING
   ========================= */

// Create order directly for food items
app.post("/api/create-direct-order", strictLimiter, async (req, res) => {
    try {
        const { item_name, amount } = req.body;

        if (!item_name || !amount) {
            return res.status(400).json({
                error: "Missing required fields",
                required: ["item_name", "amount"]
            });
        }

        const sanitizedItemName = sanitizeItemName(item_name);
        const validatedAmount = validateAmount(amount);

        const order = await razorpay.orders.create({
            amount: Math.round(validatedAmount * 100),
            currency: 'INR',
            receipt: `order_${Date.now()}`,
            notes: {
                item_name: sanitizedItemName
            }
        });

        console.log(`📝 Order created: ${order.id} for ${sanitizedItemName} | ₹${validatedAmount}`);

        res.json({
            success: true,
            order_id: order.id,
            amount: order.amount,
            currency: order.currency,
            key: RAZORPAY_KEY_ID,
            item_name: sanitizedItemName
        });

    } catch (err) {
        console.error("Order creation error:", err.message);
        res.status(500).json({ error: "Failed to create order" });
    }
});

/* =========================
   ANDROID APP ROUTES - ALL COMMENTED OUT FOR DEMO
   ========================= */

// // Authentication middleware for Android
// function authenticateAndroid(req, res, next) {
//     const authToken = req.headers['x-api-key'] ||
//         req.headers['authorization'] ||
//         req.headers['x-android-key'];
//
//     const token = authToken?.replace(/^Bearer\s+/i, '');
//
//     if (!token || token !== ANDROID_API_KEY) {
//         logSecurityEvent('AUTH_FAILED_ANDROID', {
//             ip: req.ip,
//             path: req.path,
//             providedKey: token ? token.substring(0, 8) + '...' : 'none'
//         });
//         return res.status(403).json({
//             error: "Forbidden",
//             code: "INVALID_API_KEY"
//         });
//     }
//
//     next();
// }

// // Android app creates tokens
// app.post("/api/create-token", publicApiLimiter, authenticateAndroid, (req, res) => {
//     try {
//         const { token_number, amount, items } = req.body;
//
//         if (!token_number || !amount) {
//             return res.status(400).json({
//                 error: "Missing required fields",
//                 required: ["token_number", "amount"]
//             });
//         }
//
//         // Token creation logic here...
//
//         res.json({
//             success: true,
//             token_number: token_number,
//             amount: amount,
//             message: "Token created successfully"
//         });
//
//     } catch (err) {
//         console.error("Create token error:", err.message);
//         res.status(500).json({ error: "Failed to create token" });
//     }
// });

// // Android app polls for bills to print
// app.get("/api/latest-paid-bill", publicApiLimiter, authenticateAndroid, (req, res) => {
//     // Bill polling logic here...
//     res.status(204).send();
// });

// // Android app confirms print
// app.post("/api/confirm-print", publicApiLimiter, authenticateAndroid, (req, res) => {
//     // Print confirmation logic here...
//     res.json({ success: true });
// });

/* =========================
   GENERAL ROUTES
   ========================= */

// Serve homepage (food catalogue)
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get("/health", globalLimiter, (req, res) => {
    res.json({
        status: "OK",
        uptime: process.uptime(),
        environment: NODE_ENV,
        timestamp: new Date().toISOString(),
        totalOrders: completedOrders.size
    });
});

// Debug endpoints - ONLY in development
if (NODE_ENV === 'development') {
    app.get("/debug/orders", (req, res) => {
        const orders = Array.from(completedOrders.values()).map(order => ({
            paymentId: order.paymentId,
            itemName: order.itemName,
            amount: order.amount,
            timestamp: new Date(order.timestamp).toLocaleString('en-IN')
        }));

        res.json({
            totalOrders: completedOrders.size,
            orders: orders
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
    console.log(`🍛 Food Ordering URL: http://localhost:${PORT}/`);
    console.log(`🔑 Webhook Secret: ${RAZORPAY_WEBHOOK_SECRET ? '✓ Configured' : '✗ Missing'}`);
    console.log(`💳 Razorpay: ${RAZORPAY_KEY_ID ? '✓ Configured' : '✗ Missing'}`);
    console.log(`📱 Android Integration: COMMENTED OUT FOR DEMO`);

    if (NODE_ENV === 'development') {
        console.log(`🧪 Debug endpoints enabled (dev mode)`);
    }
});
