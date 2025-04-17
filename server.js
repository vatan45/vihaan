// server.js - Main Express application
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// Initialize Razorpay
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

// MODELS
// User Model
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    pin: { type: String, required: true }, // Stored securely (hashed)
    fingerprintHash: { type: String, unique: true },
    walletBalance: { type: Number, default: 0 },
    transactions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }]
});

// Hash the PIN before saving
userSchema.pre('save', function (next) {
    if (this.isModified('pin')) {
        this.pin = crypto.createHash('sha256').update(this.pin).digest('hex');
    }
    next();
});

const User = mongoose.model('User', userSchema);

// Merchant Model
const merchantSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    upiId: { type: String, required: true },
    accountNumber: { type: String, required: true },
    ifscCode: { type: String, required: true },
    transactions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }]
});

const Merchant = mongoose.model('Merchant', merchantSchema);

// Transaction Model
const transactionSchema = new mongoose.Schema({
    amount: { type: Number, required: true },
    timestamp: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
    type: { type: String, enum: ['wallet_load', 'payment'] },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    merchant: { type: mongoose.Schema.Types.ObjectId, ref: 'Merchant' },
    razorpayPaymentId: { type: String },
    orderId: { type: String }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// ROUTES

// User Registration
app.post('/api/users/register', async (req, res) => {
    try {
        const { name, email, phone, pin } = req.body;
        const user = new User({ name, email, phone, pin });
        await user.save();
        res.status(201).json({ message: 'User registered successfully', userId: user._id });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Register fingerprint
app.post('/api/users/register-fingerprint', async (req, res) => {
    try {
        const { userId, fingerprintData } = req.body;

        // In a real system, you would process the fingerprint data and create a secure hash
        const fingerprintHash = crypto.createHash('sha256').update(fingerprintData).digest('hex');

        await User.findByIdAndUpdate(userId, { fingerprintHash });
        res.json({ message: 'Fingerprint registered successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Wallet funding - Create Razorpay order
app.post('/api/wallet/create-order', async (req, res) => {
    try {
        const { amount, userId } = req.body;

        const options = {
            amount: amount * 100, // Razorpay expects amount in paise
            currency: 'INR',
            receipt: `wallet-funding-${Date.now()}`
        };

        const order = await razorpay.orders.create(options);

        // Create a pending transaction
        const transaction = new Transaction({
            amount,
            type: 'wallet_load',
            user: userId,
            orderId: order.id
        });
        await transaction.save();

        res.json({ order });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Verify and process Razorpay payment
app.post('/api/wallet/verify-payment', async (req, res) => {
    try {
        const { razorpay_payment_id, razorpay_order_id, razorpay_signature, userId } = req.body;

        // Verify signature
        const body = razorpay_order_id + '|' + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(body)
            .digest('hex');

        if (expectedSignature !== razorpay_signature) {
            return res.status(400).json({ error: 'Invalid signature' });
        }

        // Get transaction details
        const transaction = await Transaction.findOne({ orderId: razorpay_order_id });
        if (!transaction) {
            return res.status(404).json({ error: 'Transaction not found' });
        }

        // Update transaction status
        transaction.status = 'completed';
        transaction.razorpayPaymentId = razorpay_payment_id;
        await transaction.save();

        // Update user wallet balance
        const user = await User.findById(userId);
        user.walletBalance += transaction.amount;
        user.transactions.push(transaction._id);
        await user.save();

        res.json({
            message: 'Payment successful',
            walletBalance: user.walletBalance
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Register merchant
app.post('/api/merchants/register', async (req, res) => {
    try {
        const { name, email, upiId, accountNumber, ifscCode } = req.body;
        const merchant = new Merchant({
            name,
            email,
            upiId,
            accountNumber,
            ifscCode
        });
        await merchant.save();
        res.status(201).json({ message: 'Merchant registered successfully', merchantId: merchant._id });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Initiate payment with fingerprint
app.post('/api/payment/initiate', async (req, res) => {
    try {
        // In a real scenario, you'd capture the fingerprint from a scanner
        const { fingerprintData, amount, merchantId } = req.body;

        // Find user by fingerprint hash
        const fingerprintHash = crypto.createHash('sha256').update(fingerprintData).digest('hex');
        const user = await User.findOne({ fingerprintHash });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if user has sufficient balance
        if (user.walletBalance < amount) {
            return res.status(400).json({ error: 'Insufficient wallet balance' });
        }

        // Return user details to confirm with PIN
        res.json({
            userId: user._id,
            userName: user.name,
            amount,
            merchantId,
            message: 'User authenticated by fingerprint, please enter PIN to confirm payment'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Complete payment with PIN
app.post('/api/payment/complete', async (req, res) => {
    try {
        const { userId, pin, amount, merchantId } = req.body;

        // Verify PIN
        const user = await User.findById(userId);
        const hashedPin = crypto.createHash('sha256').update(pin).digest('hex');

        if (user.pin !== hashedPin) {
            return res.status(401).json({ error: 'Invalid PIN' });
        }

        // Process payment
        const merchant = await Merchant.findById(merchantId);

        // Create transaction record
        const transaction = new Transaction({
            amount,
            type: 'payment',
            status: 'completed',
            user: userId,
            merchant: merchantId
        });
        await transaction.save();

        // Update user balance
        user.walletBalance -= amount;
        user.transactions.push(transaction._id);
        await user.save();

        // Update merchant records
        merchant.transactions.push(transaction._id);
        await merchant.save();

        // Process payout to merchant (in a real scenario, this might be batched)
        try {
            // Using Razorpay payout to transfer funds to merchant
            const payout = await razorpay.payouts.create({
                account_number: process.env.RAZORPAY_ACCOUNT_NUMBER,
                fund_account_id: merchant.accountNumber,
                amount: amount * 100, // in paise
                currency: "INR",
                mode: "UPI",
                purpose: "payout",
                reference_id: transaction._id.toString(),
            });

            // In a real implementation, you would handle payout status using webhooks

        } catch (payoutError) {
            console.error('Payout error, will need manual processing:', payoutError);
            // In a real system, you would queue this for retry or manual processing
        }

        res.json({
            message: 'Payment successful',
            transactionId: transaction._id,
            newBalance: user.walletBalance
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Offline payment handling (for when there's no internet connection)
app.post('/api/payment/offline', async (req, res) => {
    try {
        // In a real offline scenario, this would be synced when connection is restored
        // For the demo, we'll simulate storing the transaction locally and then processing
        const { fingerprintData, pin, amount, merchantId, timestamp } = req.body;

        // Find user by fingerprint hash
        const fingerprintHash = crypto.createHash('sha256').update(fingerprintData).digest('hex');
        const user = await User.findOne({ fingerprintHash });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify PIN
        const hashedPin = crypto.createHash('sha256').update(pin).digest('hex');
        if (user.pin !== hashedPin) {
            return res.status(401).json({ error: 'Invalid PIN' });
        }

        // Check if user has sufficient balance
        if (user.walletBalance < amount) {
            return res.status(400).json({ error: 'Insufficient wallet balance' });
        }

        // Process the offline payment similar to online payment
        // In a real system, this would be queued for processing once online

        const merchant = await Merchant.findById(merchantId);

        const transaction = new Transaction({
            amount,
            type: 'payment',
            status: 'completed',
            user: userId,
            merchant: merchantId,
            timestamp: timestamp || Date.now()
        });
        await transaction.save();

        user.walletBalance -= amount;
        user.transactions.push(transaction._id);
        await user.save();

        merchant.transactions.push(transaction._id);
        await merchant.save();

        res.json({
            message: 'Offline payment processed successfully',
            transactionId: transaction._id,
            newBalance: user.walletBalance
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get user wallet balance
app.get('/api/users/:userId/balance', async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ balance: user.walletBalance });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get user transaction history
app.get('/api/users/:userId/transactions', async (req, res) => {
    try {
        const transactions = await Transaction.find({ user: req.params.userId })
            .populate('merchant', 'name')
            .sort({ timestamp: -1 });
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get merchant transaction history
app.get('/api/merchants/:merchantId/transactions', async (req, res) => {
    try {
        const transactions = await Transaction.find({ merchant: req.params.merchantId })
            .populate('user', 'name')
            .sort({ timestamp: -1 });
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});