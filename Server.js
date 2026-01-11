const express = require("express");

const app = express();


/* =========================
   TEMP STORAGE (IN-MEMORY)
   ========================= */
let lastPaidBill = null;

/* =========================
   RAZORPAY WEBHOOK
   ========================= */
app.post(
    "/razorpay-webhook",
    express.raw({ type: "application/json" }),
    (req, res) => {
        try {
            const payload = JSON.parse(req.body.toString());
            const payment = payload.payload.payment.entity;

            // ✅ DEFINE customerName PROPERLY
            const customerName =
                payment.notes?.name ||
                payment.notes?.customer_name ||
                payment.notes?.customer ||
                "Guest";

            lastPaidBill = {
                orderId: payment.order_id,
                paymentId: payment.id,
                amount: payment.amount / 100,
                method: payment.method.toUpperCase(),
                customerName: customerName,
                time: new Date().toLocaleTimeString(),
                printed: false
            };

            console.log("✅ Payment stored:", lastPaidBill);
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
    if (!lastPaidBill || lastPaidBill.printed) {
        return res.status(204).send(); // nothing to print
    }

    lastPaidBill.printed = true;
    res.json(lastPaidBill);
});

/* =========================
   SERVER START
   ========================= */
const PORT = process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
});

