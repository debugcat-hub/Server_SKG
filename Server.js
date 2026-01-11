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
        const payload = JSON.parse(req.body.toString());

        // Accept only successful payments
        if (
            payload.event === "order.paid" &&
            payload.payload?.payment?.entity?.status === "captured"
        ) {
            const payment = payload.payload.payment.entity;

            lastPaidBill = {
                orderId: payment.order_id,
                paymentId: payment.id,
                amount: payment.amount / 100,
                customerName: customerName,
                method: payment.method.toUpperCase(),
                time: new Date().toLocaleTimeString(),
                printed: false
            };

            console.log("✅ PAYMENT STORED:", lastPaidBill);
        }

        res.status(200).send("OK");
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

