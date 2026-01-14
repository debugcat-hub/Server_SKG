<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SRI KRISHNA GHAR | Payment & Menu</title>
    <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --accent: #f59e0b;
            --success: #10b981;
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
            --glass: rgba(255, 255, 255, 0.06);
            --glass-border: rgba(255, 255, 255, 0.1);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }

        body {
            background: var(--bg-gradient);
            background-attachment: fixed;
            min-height: 100vh;
            color: #f8fafc;
            padding: 20px;
        }

        .container { max-width: 1200px; margin: 0 auto; }

        header {
            text-align: center;
            padding: 30px 0;
            animation: fadeInDown 0.8s ease-out;
        }

        .logo {
            font-size: 2.8rem;
            font-weight: 800;
            letter-spacing: -1px;
            background: linear-gradient(to right, #fbbf24, #f59e0b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .subtitle { color: #94a3b8; letter-spacing: 4px; font-size: 0.9rem; text-transform: uppercase; }

        /* Main Grid */
        .layout-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 30px;
            margin-top: 20px;
        }

        /* MENU SECTION */
        .menu-section {
            background: var(--glass);
            border-radius: 32px;
            padding: 30px;
            border: 1px solid var(--glass-border);
        }

        .category-title {
            color: var(--accent);
            font-size: 1.4rem;
            margin: 25px 0 15px;
            border-left: 4px solid var(--accent);
            padding-left: 15px;
        }

        .menu-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
            gap: 15px;
        }

        .menu-item {
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--glass-border);
            padding: 15px;
            border-radius: 18px;
            text-align: center;
            transition: 0.3s;
            font-size: 0.95rem;
            cursor: pointer;
            position: relative;
        }

        .menu-item:hover {
            background: var(--glass-border);
            transform: translateY(-3px);
            border-color: var(--accent);
        }

        .menu-item::after {
            content: '₹120';
            display: block;
            margin-top: 8px;
            font-weight: 700;
            color: var(--accent);
            font-size: 0.85rem;
        }

        .menu-item:active {
            transform: translateY(-1px);
        }

        /* Success Overlay */
        .success-message {
            position: fixed; 
            top: 50%; 
            left: 50%; 
            transform: translate(-50%, -50%);
            background: white; 
            color: #111; 
            padding: 40px; 
            border-radius: 30px;
            z-index: 1000; 
            display: none; 
            text-align: center; 
            width: 90%; 
            max-width: 400px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }

        .overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            z-index: 999;
            display: none;
        }

        .close-btn {
            width: 100%;
            padding: 15px;
            border-radius: 15px;
            border: none;
            background: var(--primary);
            color: white;
            font-weight: 700;
            cursor: pointer;
            margin-top: 20px;
        }

        .close-btn:hover {
            background: var(--primary-dark);
        }

        @keyframes fadeInDown { 
            from { opacity: 0; transform: translateY(-20px); } 
            to { opacity: 1; transform: translateY(0); } 
        }

        .price-note {
            text-align: center;
            color: var(--accent);
            font-weight: 600;
            margin-top: 20px;
            padding: 15px;
            background: rgba(245, 158, 11, 0.1);
            border-radius: 15px;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
    </style>
</head>
<body>

<div class="overlay" id="overlay"></div>

<div class="container">
    <header>
        <div class="logo">SRI KRISHNA GHAR</div>
        <div class="subtitle">Authentic & Pure</div>
    </header>

    <div class="layout-grid">
        <main class="menu-section">
            <h2 style="font-weight: 800; font-size: 1.8rem;">Our Menu</h2>
            <div class="price-note">🍽️ All items ₹120 | Click any item to pay</div>
            
            <div class="category-title">Signature Combos</div>
            <div class="menu-grid">
                <div class="menu-item" onclick="orderItem('Phulka combo')">Phulka combo</div>
                <div class="menu-item" onclick="orderItem('Paratha combo')">Paratha combo</div>
            </div>

            <div class="category-title">Specialty Rotis & Thepla</div>
            <div class="menu-grid">
                <div class="menu-item" onclick="orderItem('Missi roti')">Missi roti</div>
                <div class="menu-item" onclick="orderItem('Methi roti')">Methi roti</div>
                <div class="menu-item" onclick="orderItem('Palak roti')">Palak roti</div>
                <div class="menu-item" onclick="orderItem('Sattu roti')">Sattu roti</div>
                <div class="menu-item" onclick="orderItem('Beetroot roti')">Beetroot roti</div>
                <div class="menu-item" onclick="orderItem('Ragi roti')">Ragi roti</div>
                <div class="menu-item" onclick="orderItem('Jaur roti')">Jaur roti</div>
                <div class="menu-item" onclick="orderItem('Bajra roti')">Bajra roti</div>
                <div class="menu-item" onclick="orderItem('Makai roti')">Makai roti</div>
                <div class="menu-item" onclick="orderItem('Thepla')">Thepla</div>
            </div>

            <div class="category-title">Stuffed Parathas</div>
            <div class="menu-grid">
                <div class="menu-item" onclick="orderItem('Aloo paratha')">Aloo paratha</div>
                <div class="menu-item" onclick="orderItem('Sattu paratha')">Sattu paratha</div>
                <div class="menu-item" onclick="orderItem('Gobi paratha')">Gobi paratha</div>
                <div class="menu-item" onclick="orderItem('Methi paratha')">Methi paratha</div>
                <div class="menu-item" onclick="orderItem('Paneer paratha')">Paneer paratha</div>
                <div class="menu-item" onclick="orderItem('Cheese paratha')">Cheese paratha</div>
                <div class="menu-item" onclick="orderItem('Mix veg paratha')">Mix veg paratha</div>
            </div>

            <div class="category-title">Puri & Bhatura</div>
            <div class="menu-grid">
                <div class="menu-item" onclick="orderItem('Normal puri')">Normal puri</div>
                <div class="menu-item" onclick="orderItem('Chala bhatura')">Chala bhatura</div>
                <div class="menu-item" onclick="orderItem('Methi puri')">Methi puri</div>
                <div class="menu-item" onclick="orderItem('Sattu puri')">Sattu puri</div>
                <div class="menu-item" onclick="orderItem('Matar puri')">Matar puri</div>
            </div>

            <div class="category-title">Rice Specials</div>
            <div class="menu-grid">
                <div class="menu-item" onclick="orderItem('Dal chawal')">Dal chawal</div>
                <div class="menu-item" onclick="orderItem('Chola chawal')">Chola chawal</div>
                <div class="menu-item" onclick="orderItem('Rajma chawal')">Rajma chawal</div>
                <div class="menu-item" onclick="orderItem('Kadhi chawal')">Kadhi chawal</div>
                <div class="menu-item" onclick="orderItem('Veg pulao')">Veg pulao</div>
                <div class="menu-item" onclick="orderItem('Tawa pulao')">Tawa pulao</div>
                <div class="menu-item" onclick="orderItem('Jeera rice')">Jeera rice</div>
                <div class="menu-item" onclick="orderItem('Veg biryani')">Veg biryani</div>
            </div>

            <div class="category-title">Tandoor & Chat</div>
            <div class="menu-grid">
                <div class="menu-item" onclick="orderItem('Tanduri roti')">Tanduri roti</div>
                <div class="menu-item" onclick="orderItem('Butter naan')">Butter naan</div>
                <div class="menu-item" onclick="orderItem('Garlic naan')">Garlic naan</div>
                <div class="menu-item" onclick="orderItem('Stuff kulcha')">Stuff kulcha</div>
                <div class="menu-item" onclick="orderItem('Samosa')">Samosa</div>
                <div class="menu-item" onclick="orderItem('Kachori')">Kachori</div>
                <div class="menu-item" onclick="orderItem('Pani Puri')">Pani Puri</div>
                <div class="menu-item" onclick="orderItem('Vada pav')">Vada pav</div>
                <div class="menu-item" onclick="orderItem('Pav bhaji')">Pav bhaji</div>
            </div>

            <div class="category-title">Beverages</div>
            <div class="menu-grid">
                <div class="menu-item" style="border-color: var(--accent);" onclick="orderItem('Dryfruits Lassi')">Dryfruits Lassi</div>
                <div class="menu-item" style="border-color: var(--accent);" onclick="orderItem('Dryfruits Aamrash')">Dryfruits Aamrash</div>
            </div>
        </main>
    </div>

    <div id="successMessage" class="success-message">
        <div style="font-size: 50px;">✅</div>
        <h2>Payment Successful!</h2>
        <div id="successItem" style="font-size: 1.5rem; font-weight: 600; color: var(--primary); margin: 15px 0;"></div>
        <p style="color: #64748b;">Your order has been received.</p>
        <button class="close-btn" onclick="closeSuccess()">Continue Ordering</button>
    </div>
</div>

<script>
    const API_BASE = window.location.origin;
    const ITEM_PRICE = 120; // All items are ₹120

    async function orderItem(itemName) {
        try {
            // Create order on backend
            const response = await fetch(`${API_BASE}/api/create-direct-order`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    item_name: itemName,
                    amount: ITEM_PRICE
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                alert('Error: ' + (errorData.error || 'Failed to create order'));
                return;
            }

            const orderData = await response.json();

            // Initialize Razorpay payment
            const options = {
                key: orderData.key,
                amount: orderData.amount,
                currency: orderData.currency,
                name: 'SRI KRISHNA GHAR',
                description: itemName,
                order_id: orderData.order_id,
                handler: function (response) {
                    showSuccess(itemName);
                },
                prefill: {
                    name: '',
                    email: '',
                    contact: ''
                },
                theme: { 
                    color: '#6366f1' 
                },
                modal: {
                    ondismiss: function() {
                        console.log('Payment cancelled');
                    }
                }
            };

            const razorpay = new Razorpay(options);
            razorpay.open();

        } catch (error) {
            console.error('Payment error:', error);
            alert('Error initiating payment: ' + error.message);
        }
    }

    function showSuccess(itemName) {
        document.getElementById('successItem').textContent = itemName;
        document.getElementById('successMessage').style.display = 'block';
        document.getElementById('overlay').style.display = 'block';
    }

    function closeSuccess() {
        document.getElementById('successMessage').style.display = 'none';
        document.getElementById('overlay').style.display = 'none';
    }
</script>
</body>
</html>
