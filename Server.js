const express = require("express");
const crypto = require("crypto");

const app = express();

/* =========================
   CONFIG
   ========================= */
const PORT = process.env.PORT || 5000;
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET;

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
    express.raw({ type: "application/json" }),
    (req, res) => {
        try {
            /* 🔐 Verify signature */
            const receivedSignature = req.headers["x-razorpay-signature"];

            const expectedSignature = crypto
                .createHmac("sha256", RAZORPAY_WEBHOOK_SECRET)
                .update(req.body)
                .digest("hex");

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
app.get("/api/latest-paid-bill", (req, res) => {
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
app.get("/health", (req, res) => {
    res.send("OK");
});

/* =========================
   SERVER START
   ========================= */
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
