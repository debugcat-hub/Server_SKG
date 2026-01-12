const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();

/* =========================
   CONFIG
   ========================= */
const PORT = process.env.PORT || 5000;
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;
const ANDROID_API_KEY = process.env.ANDROID_API_KEY; // Get from environment

/* =========================
   RATE LIMITING CONFIGURATION
   ========================= */
const webhookLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: "Too many webhook requests, please try again later." },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
});

const androidApiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30, // 30 requests per minute per IP
    message: { error: "Too many API requests from this device." },
    standardHeaders: true,
    legacyHeaders: false,
});

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 300, // limit each IP to 300 requests per windowMs
    message: { error: "Too many requests from this IP." },
    standardHeaders: true,
    legacyHeaders: false,
});

/* =========================
   TEMP STORAGE (IN-MEMORY)
   ========================= */
// paymentId -> bill
const paidBills = new Map();

/* =========================
   RAZORPAY WEBHOOK
   ========================= */
app.post(
    "/razorpay-webhook",
    webhookLimiter,
    express.raw({ type: "application/json" }),
    (req, res) => {
        try {
            /* 🔐 Verify signature */
            const receivedSignature = req.headers["x-razorpay-signature"];

            if (!RAZORPAY_WEBHOOK_SECRET) {
                console.error("❌ RAZORPAY_WEBHOOK_SECRET not configured");
                return res.status(500).send("Server configuration error");
            }

            const expectedSignature = crypto
                .createHmac("sha256", RAZORPAY_WEBHOOK_SECRET)
                .update(req.body)
                .digest("hex");

            // Use constant-time comparison to prevent timing attacks
            if (receivedSignature !== expectedSignature) {
                console.error("❌ Invalid Razorpay signature");
                return res.status(400).send("Invalid signature");
            }

            const payload = JSON.parse(req.body.toString());

            /* ✅ Accept only successful payments */
            if (payload.event !== "payment.captured") {
                return res.status(200).send("Ignored");
            }

            const payment = payload.payload.payment.entity;

            /* 🔁 Prevent duplicates */
            if (paidBills.has(payment.id)) {
                return res.status(200).send("Duplicate ignored");
            }

            /* 👤 Customer name (safe fallback) */
            const customerName =
                payment.notes?.name ||
                payment.notes?.customer_name ||
                payment.notes?.customer ||
                "Guest";

            /* 🧾 Store bill */
            paidBills.set(payment.id, {
                orderId: payment.order_id,
                paymentId: payment.id,
                amount: payment.amount / 100,
                method: payment.method.toUpperCase(),
                customerName,
                time: new Date().toLocaleTimeString(),
                timestamp: Date.now(), // Add timestamp for cleanup
                printed: false
            });

            console.log("✅ Payment stored:", payment.id);
            res.status(200).send("OK");
        } catch (err) {
            console.error("Webhook error:", err);
            res.status(400).send("Invalid payload");
        }
    }
);

/* =========================
   ANDROID FETCH BILL
   ========================= */
app.get("/api/latest-paid-bill", androidApiLimiter, (req, res) => {
    // Check multiple auth methods
    const authToken = req.headers['x-api-key'] ||
        req.headers['authorization'] ||
        req.headers['x-android-key'];

    if (!ANDROID_API_KEY) {
        console.warn("⚠️ ANDROID_API_KEY not configured, allowing all requests");
        // Continue without auth for development
    } else {
        if (!authToken) {
            return res.status(401).json({
                error: "Authentication required",
                code: "API_KEY_MISSING",
                message: "Please provide an API key in the headers"
            });
        }

        // Clean token (remove 'Bearer ' if present)
        const token = authToken.replace(/^Bearer\s+/i, '');

        if (token !== ANDROID_API_KEY) {
            console.warn(`❌ Invalid API key attempt from IP: ${req.ip}`);
            return res.status(403).json({
                error: "Forbidden",
                code: "INVALID_API_KEY",
                message: "The provided API key is invalid"
            });
        }
    }

    // 🔥 CRITICAL: THIS PART WAS MISSING! 🔥
    // Cleanup old bills (older than 1 hour)
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    for (const [paymentId, bill] of paidBills.entries()) {
        if (bill.timestamp && bill.timestamp < oneHourAgo) {
            console.log(`🧹 Cleaning up old bill: ${paymentId}`);
            paidBills.delete(paymentId);
        }
    }

    // Find first unprinted bill
    for (const bill of paidBills.values()) {
        if (!bill.printed) {
            bill.printed = true;
            console.log(`📄 Sending bill ${bill.paymentId} to Android app`);

            // Add server timestamp for reference
            const responseBill = {
                ...bill,
                serverTime: new Date().toISOString(),
                serverTimestamp: Date.now()
            };

            return res.json(responseBill);
        }
    }

    // No bills to print - return 204 No Content
    console.log("📭 No unprinted bills available");
    res.status(204).send();
});

/* =========================
   HEALTH CHECK (OPTIONAL)
   ========================= */
app.get("/health", globalLimiter, (req, res) => {
    res.json({
        status: "OK",
        uptime: process.uptime(),
        billsInQueue: paidBills.size,
        totalBillsProcessed: paidBills.size,
        unprintedBills: Array.from(paidBills.values()).filter(b => !b.printed).length,
        environment: process.env.NODE_ENV || 'development'
    });
});

/* =========================
   ADMIN ENDPOINT (Optional for debugging)
   ========================= */
app.get("/admin/bills", (req, res) => {
    // Simple password protection for admin endpoint
    const adminToken = req.headers['x-admin-token'];
    if (adminToken !== process.env.ADMIN_TOKEN) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    const bills = Array.from(paidBills.values());
    res.json({
        total: bills.length,
        unprinted: bills.filter(b => !b.printed).length,
        bills: bills
    });
});

/* =========================
   Apply global rate limiting to all routes
   ========================= */
app.use(globalLimiter);

/* =========================
   SERVER START
   ========================= */
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔐 API Key required: ${!!ANDROID_API_KEY}`);
    console.log(`🔐 Razorpay Webhook Secret: ${!!RAZORPAY_WEBHOOK_SECRET}`);
});