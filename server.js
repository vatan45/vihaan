// server.js - Main Express application
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');
const bcrypt = require('bcrypt');

dotenv.config();
const app = express();

// Middleware
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Accept', 'Access-Control-Allow-Origin', 'Authorization'],
    credentials: false
};

app.use(cors(corsOptions));
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
    fingerprintHash: {
        type: String,
        unique: false,
        sparse: true  // This ensures uniqueness is only enforced on non-null values
    },
    walletBalance: { type: Number, default: 0 },
    transactions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }],
    webauthnCredentials: [{ type: mongoose.Schema.Types.ObjectId, ref: 'WebAuthnCredential' }],
    currentChallenge: { type: String }
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
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
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

// WebAuthn Credential Model
const webauthnCredentialSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    credentialID: { type: String, required: true, unique: true },
    credentialPublicKey: { type: String, required: true },
    counter: { type: Number, default: 0 },
    deviceType: { type: String },
    lastUsed: { type: Date, default: Date.now }
});

const WebAuthnCredential = mongoose.model('WebAuthnCredential', webauthnCredentialSchema);

// WebAuthn Configuration
const rpName = 'Payment App';
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || `https://${rpID}:3000`;

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
        const { razorpay_payment_id, razorpay_order_id, userId } = req.body;

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
        const { username, password, name, email, upiId, accountNumber, ifscCode } = req.body;

        // Hash the password before storing
        const hashedPassword = await bcrypt.hash(password, 10);

        const merchant = new Merchant({
            username,
            password: hashedPassword,  // Store the hashed password
            name,
            email,
            upiId,
            accountNumber,
            ifscCode,
        });
        await merchant.save();
        res.status(201).json({ message: 'Merchant registered successfully', merchantId: merchant._id });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Initiate payment with fingerprint and PIN
app.post('/api/payment/initiate', async (req, res) => {
    try {
        // Get both fingerprint and PIN in initial request
        const { fingerprintData, pin, amount, merchantId } = req.body;

        // Find user by fingerprint hash
        const fingerprintHash = crypto.createHash('sha256').update(fingerprintData).digest('hex');
        const hashedPin = crypto.createHash('sha256').update(pin).digest('hex');

        // Find user that matches both fingerprint and PIN
        const user = await User.findOne({
            fingerprintHash: fingerprintHash,
            pin: hashedPin
        });

        if (!user) {
            return res.status(401).json({ error: 'Invalid fingerprint or PIN' });
        }

        // Check if user has sufficient balance
        if (user.walletBalance < amount) {
            return res.status(400).json({ error: 'Insufficient wallet balance' });
        }

        // Process payment
        const merchant = await Merchant.findById(merchantId);
        if (!merchant) {
            return res.status(404).json({ error: 'Merchant not found' });
        }

        // Create transaction record
        const transaction = new Transaction({
            amount,
            type: 'payment',
            status: 'completed',
            user: user._id,
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

        // Process payout to merchant
        try {
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

// Get calculated wallet balance from transactions
app.get('/api/users/:userId/calculated-balance', async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get all transactions for the user
        const transactions = await Transaction.find({ user: user._id });

        // Calculate balance from transactions
        let calculatedBalance = 0;
        transactions.forEach(transaction => {
            if (transaction.status === 'completed') {
                if (transaction.type === 'wallet_load') {
                    calculatedBalance += transaction.amount;
                } else if (transaction.type === 'payment') {
                    calculatedBalance -= transaction.amount;
                }
            }
        });

        res.json({
            storedBalance: user.walletBalance,
            calculatedBalance: calculatedBalance,
            transactions: transactions.length
        });
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

// WebAuthn Routes
app.post('/api/webauthn/generate-registration-options', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userAuthenticators = await WebAuthnCredential.find({ user: user._id });

        const options = await generateRegistrationOptions({
            rpName,
            rpID,
            userID: user._id.toString(),
            userName: user.email,
            userDisplayName: user.name,
            attestationType: 'none',
            authenticatorSelection: {
                authenticatorAttachment: 'platform',
                userVerification: 'required',
                requireResidentKey: false,
            },
            excludeCredentials: userAuthenticators.map(authenticator => ({
                id: isoBase64URL.toBuffer(authenticator.credentialID),
                type: 'public-key',
                transports: ['internal'],
            })),
        });

        // Store the challenge in the user document
        user.currentChallenge = options.challenge;
        await user.save();

        res.json(options);
    } catch (error) {
        console.error('Error generating registration options:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/webauthn/verify-registration', async (req, res) => {
    try {
        const { email, credential } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const expectedChallenge = user.currentChallenge;

        let verification;
        try {
            verification = await verifyRegistrationResponse({
                credential,
                expectedChallenge,
                expectedOrigin: origin,
                expectedRPID: rpID,
                requireUserVerification: true,
            });
        } catch (error) {
            console.error('Error verifying registration:', error);
            return res.status(400).json({ error: error.message });
        }

        const { verified, registrationInfo } = verification;

        if (verified && registrationInfo) {
            const { credentialPublicKey, credentialID, counter } = registrationInfo;

            const newCredential = new WebAuthnCredential({
                user: user._id,
                credentialID: isoBase64URL.fromBuffer(credentialID),
                credentialPublicKey: isoBase64URL.fromBuffer(credentialPublicKey),
                counter,
                deviceType: 'platform',
            });

            await newCredential.save();
            user.webauthnCredentials.push(newCredential._id);
            await user.save();
        }

        res.json({ verified });
    } catch (error) {
        console.error('Error in verify registration:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/webauthn/generate-authentication-options', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email }).populate('webauthnCredentials');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userAuthenticators = user.webauthnCredentials;

        const options = await generateAuthenticationOptions({
            rpID,
            allowCredentials: userAuthenticators.map(authenticator => ({
                id: isoBase64URL.toBuffer(authenticator.credentialID),
                type: 'public-key',
                transports: ['internal'],
            })),
            userVerification: 'required',
        });

        // Store the challenge in the user document
        user.currentChallenge = options.challenge;
        await user.save();

        res.json(options);
    } catch (error) {
        console.error('Error generating authentication options:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/webauthn/verify-authentication', async (req, res) => {
    try {
        const { email, credential, amount, merchantId } = req.body;
        const user = await User.findOne({ email }).populate('webauthnCredentials');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const expectedChallenge = user.currentChallenge;
        const authenticator = user.webauthnCredentials.find(
            cred => cred.credentialID === credential.id
        );

        if (!authenticator) {
            return res.status(400).json({ error: 'Authenticator not found' });
        }

        let verification;
        try {
            verification = await verifyAuthenticationResponse({
                credential,
                expectedChallenge,
                expectedOrigin: origin,
                expectedRPID: rpID,
                authenticator: {
                    credentialPublicKey: isoBase64URL.toBuffer(authenticator.credentialPublicKey),
                    credentialID: isoBase64URL.toBuffer(authenticator.credentialID),
                    counter: authenticator.counter,
                },
                requireUserVerification: true,
            });
        } catch (error) {
            console.error('Error verifying authentication:', error);
            return res.status(400).json({ error: error.message });
        }

        const { verified, authenticationInfo } = verification;

        if (verified) {
            // Update authenticator counter
            authenticator.counter = authenticationInfo.newCounter;
            authenticator.lastUsed = new Date();
            await authenticator.save();

            // Process payment if amount and merchantId are provided
            if (amount && merchantId) {
                const merchant = await Merchant.findById(merchantId);

                if (!merchant) {
                    return res.status(404).json({ error: 'Merchant not found' });
                }

                if (user.walletBalance < amount) {
                    return res.status(400).json({ error: 'Insufficient wallet balance' });
                }

                // Create transaction record
                const transaction = new Transaction({
                    amount,
                    type: 'payment',
                    status: 'completed',
                    user: user._id,
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

                // Process payout to merchant
                try {
                    const payout = await razorpay.payouts.create({
                        account_number: process.env.RAZORPAY_ACCOUNT_NUMBER,
                        fund_account_id: merchant.accountNumber,
                        amount: amount * 100,
                        currency: "INR",
                        mode: "UPI",
                        purpose: "payout",
                        reference_id: transaction._id.toString(),
                    });
                } catch (payoutError) {
                    console.error('Payout error:', payoutError);
                }

                return res.json({
                    verified: true,
                    message: 'Payment successful',
                    transactionId: transaction._id,
                    newBalance: user.walletBalance
                });
            }

            return res.json({ verified: true });
        }

        res.json({ verified: false });
    } catch (error) {
        console.error('Error in verify authentication:', error);
        res.status(500).json({ error: error.message });
    }
});
const authenticateMerchant = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.merchantId = decoded.merchantId;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};
// Merchant Login
app.post('/api/merchants/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find merchant by username
        const merchant = await Merchant.findOne({ username });
        if (!merchant) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, merchant.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { merchantId: merchant._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            merchant: {
                id: merchant._id,
                name: merchant.name,
                email: merchant.email
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get user by fingerprint hash
app.get('/api/users/by-fingerprint', async (req, res) => {
    try {
        const { fingerprintHash } = req.query;

        if (!fingerprintHash) {
            return res.status(400).json({ error: 'Fingerprint hash is required' });
        }

        // Find user by fingerprint hash
        const user = await User.findOne({ fingerprintHash });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Return user information (excluding sensitive data)
        res.json({
            userId: user._id,
            name: user.name,
            email: user.email,
            walletBalance: user.walletBalance
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Start the server
const PORT = process.env.PORT || 5004;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 