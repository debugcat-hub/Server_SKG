const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const Razorpay = require("razorpay");
const path = require("path");

const app = express();

/* =========================
   CONFIG
   ========================= */
const PORT = process.env.PORT || 5000;
const RAZORPAY_WEBHOOK_SECRET = '1234567890'; // Your actual secret
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID||'rzp_test_S3I4542jRUgPsp';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET||'H6dYHbF4MhSnVVSQ4IwktSCV';
const ANDROID_API_KEY = process.env.ANDROID_API_KEY||'hello_people';

/* =========================
   INITIALIZE RAZORPAY
   ========================= */
const razorpay = new Razorpay({
    key_id: RAZORPAY_KEY_ID,
    key_secret: RAZORPAY_KEY_SECRET
});

/* =========================
   RATE LIMITING
   ========================= */
const webhookLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Too many webhook requests" },
    standardHeaders: true,
    legacyHeaders: false,
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

/* =========================
   STORAGE
   ========================= */
const pendingTokens = new Map();
const paidBills = new Map();

/* =========================
   MIDDLEWARE - CRITICAL ORDER!
   ========================= */
app.set('trust proxy', 1);

// Static files first
app.use(express.static(path.join(__dirname, 'public')));

// WEBHOOK ROUTE MUST COME BEFORE express.json()
// This is the critical fix!
app.post(
    "/razorpay-webhook",
    webhookLimiter,
    express.raw({ type: "application/json" }),
    (req, res) => {
        console.log("📨 Webhook received at:", new Date().toISOString());

        const receivedSignature = req.headers["x-razorpay-signature"];

        if (!receivedSignature) {
            console.error("❌ No signature provided");
            return res.status(400).send("Missing signature");
        }

        try {
            // Get raw body as string
            const rawBody = req.body.toString('utf8');

            console.log("📦 Body type:", typeof req.body, "| Is Buffer:", Buffer.isBuffer(req.body));
            console.log("📦 Raw body length:", rawBody.length);
            console.log("📝 First 200 chars:", rawBody.substring(0, 200));

            // Verify signature
            const expectedSignature = crypto
                .createHmac("sha256", RAZORPAY_WEBHOOK_SECRET)
                .update(rawBody)
                .digest("hex");

            console.log("🔐 Received:", receivedSignature);
            console.log("🔐 Expected:", expectedSignature);

            if (receivedSignature !== expectedSignature) {
                console.error("❌ Signature mismatch!");
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
            const tokenNumber = payment.notes?.token_number || 'Unknown';

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
                customerName: payment.notes?.customer_name ||
                    payment.email?.split('@')[0] || 'Guest',
                customerEmail: payment.email || '',
                customerPhone: payment.contact || '',
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
            }

            const unprintedCount = Array.from(paidBills.values()).filter(b => !b.printed).length;
            console.log(`✅ Bill stored! Unprinted: ${unprintedCount}`);
            console.log(`📋 Bill details:`, JSON.stringify({
                paymentId: payment.id,
                tokenNumber: tokenNumber,
                amount: payment.amount / 100,
                printed: false
            }, null, 2));

            res.status(200).json({ success: true });

        } catch (err) {
            console.error("❌ Webhook error:", err.message);
            res.status(400).send("Error");
        }
    }
);

// NOW apply JSON parsing for all OTHER routes
app.use(express.json());

/* =========================
   ALL OTHER ROUTES BELOW
   ========================= */

app.post("/api/create-token", androidApiLimiter, (req, res) => {
    const authToken = req.headers['x-api-key'] ||
        req.headers['authorization'] ||
        req.headers['x-android-key'];

    if (ANDROID_API_KEY && authToken?.replace(/^Bearer\s+/i, '') !== ANDROID_API_KEY) {
        return res.status(403).json({
            error: "Forbidden",
            code: "INVALID_API_KEY"
        });
    }

    try {
        const { token_number, amount, items } = req.body;

        if (!token_number || !amount) {
            return res.status(400).json({
                error: "Missing required fields",
                required: ["token_number", "amount"]
            });
        }

        pendingTokens.set(token_number, {
            tokenNumber: token_number,
            amount: parseFloat(amount),
            items: items || [],
            createdAt: Date.now(),
            status: 'pending'
        });

        console.log(`✅ Token created: ${token_number} | Amount: ₹${amount}`);

        res.json({
            success: true,
            token_number: token_number,
            amount: amount,
            message: "Token created successfully"
        });

    } catch (err) {
        console.error("Create token error:", err);
        res.status(500).json({ error: "Failed to create token" });
    }
});

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

app.post("/api/create-order", async (req, res) => {
    try {
        const { token_number } = req.body;

        const token = pendingTokens.get(token_number);
        if (!token) {
            return res.status(404).json({
                error: "Token not found"
            });
        }

        if (token.status !== 'pending') {
            return res.status(400).json({
                error: "Token already paid"
            });
        }

        const order = await razorpay.orders.create({
            amount: Math.round(token.amount * 100),
            currency: 'INR',
            receipt: `token_${token_number}_${Date.now()}`,
            notes: {
                token_number: token_number.toString()
            }
        });

        console.log(`📝 Order created: ${order.id} for Token: ${token_number}`);

        res.json({
            success: true,
            order_id: order.id,
            amount: order.amount,
            currency: order.currency,
            key: RAZORPAY_KEY_ID,
            token_number: token_number
        });

    } catch (err) {
        console.error("Order creation error:", err);
        res.status(500).json({ error: "Failed to create order" });
    }
});

/* =========================
   ANDROID - FETCH LATEST PAID BILL (FIXED!)
   ========================= */
app.get("/api/latest-paid-bill", androidApiLimiter, (req, res) => {
    const authToken = req.headers['x-api-key'] ||
        req.headers['authorization'] ||
        req.headers['x-android-key'];

    if (ANDROID_API_KEY) {
        const token = authToken?.replace(/^Bearer\s+/i, '');
        if (token !== ANDROID_API_KEY) {
            console.log("❌ Invalid API key from Android");
            return res.status(403).json({
                error: "Forbidden",
                code: "INVALID_API_KEY"
            });
        }
    }

    const currentTime = new Date().toLocaleTimeString('en-IN', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    console.log(`📱 Android polling at: ${currentTime}`);

    // Cleanup old bills (older than 2 hours)
    const twoHoursAgo = Date.now() - (2 * 60 * 60 * 1000);
    for (const [paymentId, bill] of paidBills.entries()) {
        if (bill.timestamp && bill.timestamp < twoHoursAgo) {
            console.log(`🧹 Cleaning up old bill: ${paymentId}`);
            paidBills.delete(paymentId);
        }
    }

    // Find first unprinted bill (oldest first)
    const unprintedBills = Array.from(paidBills.values())
        .filter(b => !b.printed)
        .sort((a, b) => a.timestamp - b.timestamp);

    const totalBills = paidBills.size;
    const unprintedCount = unprintedBills.length;

    console.log(`📊 Bills status - Total: ${totalBills}, Unprinted: ${unprintedCount}`);

    if (unprintedBills.length > 0) {
        const bill = unprintedBills[0];

        // DON'T mark as printed yet - only increment attempt counter
        bill.printAttempts = (bill.printAttempts || 0) + 1;
        bill.lastPrintAttempt = Date.now();

        console.log(`📤 Sending bill to Android:`);
        console.log(`   Payment ID: ${bill.paymentId}`);
        console.log(`   Token: ${bill.tokenNumber}`);
        console.log(`   Amount: ₹${bill.amount}`);
        console.log(`   Attempt: ${bill.printAttempts}`);
        console.log(`   Items:`, bill.items);

        const responseData = {
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
        };

        console.log(`📦 Response payload:`, JSON.stringify(responseData, null, 2));

        return res.json(responseData);
    }

    // No unprinted bills
    console.log("✅ No unprinted bills available (204 response)");
    res.status(204).send();
});

/* =========================
   ANDROID - CONFIRM BILL PRINTED (FIXED!)
   ========================= */
app.post("/api/confirm-print", androidApiLimiter, (req, res) => {
    const authToken = req.headers['x-api-key'] ||
        req.headers['authorization'] ||
        req.headers['x-android-key'];

    if (ANDROID_API_KEY) {
        const token = authToken?.replace(/^Bearer\s+/i, '');
        if (token !== ANDROID_API_KEY) {
            return res.status(403).json({
                error: "Forbidden",
                code: "INVALID_API_KEY"
            });
        }
    }

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

            console.log(`✅ Print confirmed for payment: ${paymentId} (Token: ${bill.tokenNumber})`);
            console.log(`📊 Remaining unprinted bills: ${unprintedCount}`);

            res.json({
                success: true,
                message: "Print confirmed",
                unprintedBills: unprintedCount
            });
        } else {
            console.log(`❌ Bill not found for confirmation: ${paymentId}`);
            res.status(404).json({ error: "Bill not found" });
        }

    } catch (err) {
        console.error("Confirm print error:", err);
        res.status(500).json({ error: "Failed to confirm print" });
    }
});

app.get("/payment", (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'payment.html'));
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'payment.html'));
});

app.get("/health", globalLimiter, (req, res) => {
    const unprintedCount = Array.from(paidBills.values()).filter(b => !b.printed).length;
    res.json({
        status: "OK",
        uptime: process.uptime(),
        pendingTokens: pendingTokens.size,
        unprintedBills: unprintedCount,
        totalBills: paidBills.size
    });
});

/* =========================
   DEBUG ENDPOINT - View all bills
   ========================= */
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

/* =========================
   TEST ENDPOINT - Create fake bill for testing
   ========================= */
app.get("/test/create-fake-bill", (req, res) => {
    const fakePaymentId = "pay_test_" + Date.now();
    const fakeTokenNumber = req.query.token || String(Math.floor(1000 + Math.random() * 9000));
    const fakeAmount = parseFloat(req.query.amount) || 100;

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
        message: "Fake bill created. Android should print it within 8 seconds."
    });
});

/* =========================
   TEST ENDPOINT - Mark bill as unprinted (for testing)
   ========================= */
app.post("/test/mark-unprinted", (req, res) => {
    const { paymentId } = req.body;

    if (!paymentId) {
        return res.status(400).json({ error: "Missing paymentId" });
    }

    const bill = paidBills.get(paymentId);
    if (bill) {
        bill.printed = false;
        bill.printAttempts = 0;
        console.log(`🔄 TEST: Marked bill as unprinted - Payment: ${paymentId}, Token: ${bill.tokenNumber}`);
        res.json({ success: true, message: "Bill marked as unprinted" });
    } else {
        res.status(404).json({ error: "Bill not found" });
    }
});

app.get("/admin/bills", (req, res) => {
    const adminToken = req.headers['x-admin-token'];
    if (adminToken !== process.env.ADMIN_TOKEN) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    const pending = Array.from(pendingTokens.values());
    const paid = Array.from(paidBills.values());

    res.json({
        pendingTokens: pending,
        paidBills: paid,
        totalPending: pending.length,
        totalUnprinted: paid.filter(b => !b.printed).length
    });
});

app.use(globalLimiter);

app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔑 API Key: ${!!ANDROID_API_KEY}`);
    console.log(`🔐 Webhook Secret: ${!!RAZORPAY_WEBHOOK_SECRET}`);
    console.log(`💳 Razorpay: ${!!RAZORPAY_KEY_ID}`);
    console.log(`📱 Payment URL: http://localhost:${PORT}/payment`);
    console.log(`🧪 Test endpoints:`);
    console.log(`   GET  /test/create-fake-bill?token=1234&amount=100`);
    console.log(`   GET  /debug/bills`);
    console.log(`   POST /test/mark-unprinted {"paymentId": "pay_xxx"}`);
});
