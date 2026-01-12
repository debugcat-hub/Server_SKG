const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();

/* =========================
   CONFIG
   ========================= */
const PORT = process.env.PORT || 5000;
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;

/* =========================
   RATE LIMITING CONFIGURATION
   ========================= */
const webhookLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: "Too many webhook requests, please try again later." },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false, // count all requests
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
    webhookLimiter, // Add rate limiting here
    express.raw({ type: "application/json" }),
    (req, res) => {
        try {
            /* 🔐 Verify signature */
            const receivedSignature = req.headers["x-razorpay-signature"];

            // Also verify the webhook secret exists
            if (!RAZORPAY_WEBHOOK_SECRET) {
                console.error("❌ RAZORPAY_WEBHOOK_SECRET not configured");
                return res.status(500).send("Server configuration error");
            }

            const expectedSignature = crypto
                .createHmac("sha256", RAZORPAY_WEBHOOK_SECRET)
                .update(req.body)
                .digest("hex");

            // Use constant-time comparison to prevent timing attacks
            const isSignatureValid = crypto.timingSafeEqual(
                Buffer.from(receivedSignature),
                Buffer.from(expectedSignature)
            );

            if (!isSignatureValid) {
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
    // Optional: Add API key or basic auth for Android app
    const authToken = req.headers['x-api-key'];
    if (process.env.ANDROID_API_KEY && authToken !== process.env.ANDROID_API_KEY) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    // Cleanup old bills (older than 1 hour)
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    for (const [paymentId, bill] of paidBills.entries()) {
        if (bill.timestamp && bill.timestamp < oneHourAgo) {
            paidBills.delete(paymentId);
        }
    }

    for (const bill of paidBills.values()) {
        if (!bill.printed) {
            bill.printed = true;
            return res.json(bill);
        }
    }
    res.status(204).send(); // nothing to print
});

/* =========================
   HEALTH CHECK (OPTIONAL)
   ========================= */
app.get("/health", globalLimiter, (req, res) => {
    res.json({
        status: "OK",
        uptime: process.uptime(),
        billsInQueue: paidBills.size
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
});