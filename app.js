"use strict";

const path = require("node:path");
const fs = require("node:fs");
const { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } = require("node:crypto");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const express = require("express");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const helmet = require("helmet");

const isProduction = process.env.NODE_ENV === "production";
const dataDirectory = path.join(__dirname, ".private");
fs.mkdirSync(dataDirectory, { recursive: true });

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.length < 32) {
    throw new Error("SESSION_SECRET must be at least 32 characters.");
}

let bankEncryptionKey = process.env.BANK_DETAILS_ENCRYPTION_KEY || "";
if (!/^[a-f0-9]{64}$/i.test(bankEncryptionKey)) {
    throw new Error("BANK_DETAILS_ENCRYPTION_KEY must be a 64-character hexadecimal key.");
}
bankEncryptionKey = Buffer.from(bankEncryptionKey, "hex");

const app = express();
const port = Number(process.env.PORT || 3000);
const mediaDirectory = path.join(__dirname, "uploads", "media");
fs.mkdirSync(mediaDirectory, { recursive: true });

// ========== MONGOOSE MODELS ==========
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, maxlength: 50 },
    phone: { type: String, required: true, unique: true },
    password_hash: { type: String, required: true },
    balance_paise: { type: Number, default: 0 },
    status: { type: String, default: "active", enum: ["active", "suspended"] },
    referral_code: { type: String, unique: true, sparse: true },
    referred_by_user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
}, { timestamps: true });
const User = mongoose.model("User", userSchema);

const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password_hash: { type: String, required: true },
    password_change_required: { type: Boolean, default: true },
    last_login_at: Date
}, { timestamps: true });
const Admin = mongoose.model("Admin", adminSchema);

const productSchema = new mongoose.Schema({
    name: String,
    category: { type: String, enum: ["daily", "vip"] },
    price_paise: Number,
    duration_days: Number,
    daily_reward_paise: { type: Number, default: 0 },
    total_reward_paise: { type: Number, default: 0 },
    purchase_limit: { type: Number, default: 1 },
    active: { type: Boolean, default: true },
    image_url: { type: String, default: "" }
}, { timestamps: true });
const Product = mongoose.model("Product", productSchema);

const missionSchema = new mongoose.Schema({
    name: String,
    description: { type: String, default: "" },
    target_members: Number,
    reward_paise: Number,
    active: { type: Boolean, default: true }
}, { timestamps: true });
const Mission = mongoose.model("Mission", missionSchema);

const walletTransactionSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    type: { type: String, enum: ["recharge", "withdrawal", "adjustment"] },
    amount_paise: Number,
    status: { type: String, enum: ["pending", "processing", "approved", "rejected"] },
    reference: { type: String, default: "" },
    note: { type: String, default: "" },
    created_by_admin_id: { type: mongoose.Schema.Types.ObjectId, ref: "Admin", default: null },
    reviewed_by_admin_id: { type: mongoose.Schema.Types.ObjectId, ref: "Admin", default: null },
    reviewed_at: Date
}, { timestamps: true });
const WalletTransaction = mongoose.model("WalletTransaction", walletTransactionSchema);

const siteSettingSchema = new mongoose.Schema({
    key: { type: String, unique: true, required: true },
    value: String,
    updated_by_admin_id: { type: mongoose.Schema.Types.ObjectId, ref: "Admin", default: null }
}, { timestamps: true });
const SiteSetting = mongoose.model("SiteSetting", siteSettingSchema);

const adminAuditSchema = new mongoose.Schema({
    admin_id: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
    action: String,
    entity_type: String,
    entity_id: String,
    details_json: { type: String, default: "{}" }
}, { timestamps: true });
const AdminAudit = mongoose.model("AdminAudit", adminAuditSchema);

const missionClaimSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    mission_id: { type: mongoose.Schema.Types.ObjectId, ref: "Mission" },
    status: { type: String, enum: ["pending", "approved", "rejected"] },
    note: { type: String, default: "" },
    reviewed_by_admin_id: { type: mongoose.Schema.Types.ObjectId, ref: "Admin", default: null },
    reviewed_at: Date
}, { timestamps: true });
missionClaimSchema.index({ user_id: 1, mission_id: 1 }, { unique: true });
const MissionClaim = mongoose.model("MissionClaim", missionClaimSchema);

const productRequestSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    product_id: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
    product_name: String,
    price_paise: Number,
    status: { type: String, enum: ["pending", "approved", "rejected"] },
    note: { type: String, default: "" },
    reviewed_by_admin_id: { type: mongoose.Schema.Types.ObjectId, ref: "Admin", default: null },
    reviewed_at: Date
}, { timestamps: true });
const ProductRequest = mongoose.model("ProductRequest", productRequestSchema);

const demoAccountSchema = new mongoose.Schema({
    demo_code: { type: String, unique: true },
    name: String,
    balance_paise: { type: Number, default: 0 },
    created_by_admin_id: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" }
}, { timestamps: true });
const DemoAccount = mongoose.model("DemoAccount", demoAccountSchema);

const demoWalletTransactionSchema = new mongoose.Schema({
    demo_account_id: { type: mongoose.Schema.Types.ObjectId, ref: "DemoAccount" },
    type: { type: String, enum: ["demo_deposit", "demo_withdrawal"] },
    amount_paise: Number,
    note: String,
    created_by_admin_id: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" }
}, { timestamps: true });
const DemoWalletTransaction = mongoose.model("DemoWalletTransaction", demoWalletTransactionSchema);

const bankAccountSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", unique: true },
    holder_name: String,
    bank_name: String,
    account_ciphertext: String,
    account_iv: String,
    account_tag: String,
    account_last4: String,
    ifsc: String
}, { timestamps: true });
const BankAccount = mongoose.model("BankAccount", bankAccountSchema);

const userProductSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    product_id: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
    product_name: String,
    price_paise: Number,
    duration_days: Number,
    purchased_at: { type: Date, default: Date.now },
    expires_at: Date,
    status: { type: String, default: "active", enum: ["active", "expired"] }
}, { timestamps: true });
const UserProduct = mongoose.model("UserProduct", userProductSchema);

const sessionSchema = new mongoose.Schema({
    _id: String,
    expires: Date,
    data: String
});
const SessionModel = mongoose.model("Session", sessionSchema);

// ========== SESSION STORE ==========
class MongoSessionStore extends session.Store {
    async get(sid, cb) {
        try {
            const row = await SessionModel.findById(sid);
            cb(null, row && row.expires > new Date() ? JSON.parse(row.data) : null);
        } catch (e) { cb(e); }
    }
    async set(sid, val, cb) {
        try {
            const expires = val.cookie?.expires ? new Date(val.cookie.expires) : new Date(Date.now() + 86400000);
            await SessionModel.findByIdAndUpdate(sid, { expires, data: JSON.stringify(val) }, { upsert: true });
            cb(null);
        } catch (e) { cb(e); }
    }
    async touch(sid, val, cb) {
        try {
            const expires = val.cookie?.expires ? new Date(val.cookie.expires) : new Date(Date.now() + 86400000);
            await SessionModel.findByIdAndUpdate(sid, { expires });
            cb(null);
        } catch (e) { cb(e); }
    }
    async destroy(sid, cb) {
        try { await SessionModel.findByIdAndDelete(sid); cb(null); } catch (e) { cb(e); }
    }
}

// ========== MIDDLEWARE ==========
app.disable("x-powered-by");
if (isProduction) app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "10kb" }));
app.use(session({
    name: "kingfisher.sid",
    secret: sessionSecret,
    store: new MongoSessionStore(),
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: isProduction, sameSite: "strict", maxAge: 86400000 }
}));

function asyncRoute(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }
function createCsrfToken() { return randomBytes(32).toString("hex"); }
function tokenMatches(expected, supplied) {
    if (typeof supplied !== "string" || !/^[a-f0-9]{64}$/i.test(supplied)) return false;
    const a = Buffer.from(expected, "hex");
    const b = Buffer.from(supplied, "hex");
    return a.length === b.length && timingSafeEqual(a, b);
}
function requireCsrf(req, res, next) {
    if (!req.session.csrfToken || !tokenMatches(req.session.csrfToken, req.get("X-CSRF-Token"))) {
        return res.status(403).json({ success: false, message: "Session expired. Refresh and try again." });
    }
    next();
}
async function requireAuth(req, res, next) {
    if (!req.session.user) return res.status(401).json({ success: false, message: "Please log in first." });
    const user = await User.findById(req.session.user.id);
    if (!user || user.status !== "active") {
        req.session.destroy(() => {});
        return res.status(401).json({ success: false, message: "This account is unavailable." });
    }
    next();
}
function requireAdmin(req, res, next) {
    if (!req.session.admin) return res.status(401).json({ success: false, message: "Admin login required." });
    next();
}
async function auditAdmin(adminId, action, entityType, entityId, details) {
    await AdminAudit.create({ admin_id: adminId, action, entity_type: entityType, entity_id: String(entityId || ""), details_json: JSON.stringify(details || {}) });
}
function parseRupees(value) {
    const amount = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(amount) || Math.abs(amount) > 10000000) return null;
    const paise = Math.round(amount * 100);
    return Number.isSafeInteger(paise) ? paise : null;
}
function encryptBankAccount(accountNumber) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", bankEncryptionKey, iv);
    const ciphertext = Buffer.concat([cipher.update(accountNumber, "utf8"), cipher.final()]);
    return { ciphertext: ciphertext.toString("hex"), iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex") };
}
function decryptBankAccount(record) {
    const decipher = createDecipheriv("aes-256-gcm", bankEncryptionKey, Buffer.from(record.account_iv, "hex"));
    decipher.setAuthTag(Buffer.from(record.account_tag, "hex"));
    return Buffer.concat([decipher.update(Buffer.from(record.account_ciphertext, "hex")), decipher.final()]).toString("utf8");
}
async function createReferralCode() {
    let code;
    do { code = randomBytes(5).toString("hex").toUpperCase(); }
    while (await User.findOne({ referral_code: code }));
    return code;
}
async function countActiveTeamMembers(userId) {
    const level1 = await User.find({ referred_by_user_id: userId, status: "active" }).select("_id");
    const l1ids = level1.map(u => u._id);
    const level2 = await User.find({ referred_by_user_id: { $in: l1ids }, status: "active" }).select("_id");
    const l2ids = level2.map(u => u._id);
    const level3 = await User.find({ referred_by_user_id: { $in: l2ids }, status: "active" }).select("_id");
    return level1.length + level2.length + level3.length;
} // ========== RATE LIMITERS ==========
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { success: false, message: "Too many attempts. Please try again later." }
});
const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 8,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { success: false, message: "Too many admin login attempts. Try again later." }
});

// ========== PUBLIC ROUTES ==========
app.get("/api/csrf", asyncRoute(async (req, res) => {
    if (!req.session.csrfToken) req.session.csrfToken = createCsrfToken();
    res.set("Cache-Control", "no-store");
    res.json({ csrfToken: req.session.csrfToken });
}));

app.get("/api/public/settings", asyncRoute(async (req, res) => {
    const settings = await SiteSetting.find({
        key: { $in: ["site_name", "site_logo_url", "site_banner_url", "invite_banner_url", "site_spinner_url", "minimum_recharge_rupees", "minimum_withdrawal_rupees", "support_url"] }
    });
    const settingsObj = Object.fromEntries(settings.map(s => [s.key, s.value]));
    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        settings: Object.assign({
            payment_provider: "manual",
            payment_gateway_enabled: "0",
            payment_gateway_mode: "manual"
        }, settingsObj)
    });
}));

// ========== AUTH ROUTES ==========
app.post("/api/register", authLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const phone = typeof req.body.phone === "string" ? req.body.phone : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const referralCode = typeof req.body.referralCode === "string" ? req.body.referralCode.trim().toUpperCase() : "";

    if (!name || name.length > 50) return res.status(400).json({ success: false, message: "Enter a name up to 50 characters." });
    if (!/^\d{10}$/.test(phone)) return res.status(400).json({ success: false, message: "Enter a valid 10 digit mobile number." });
    if (password.length < 6 || password.length > 64) return res.status(400).json({ success: false, message: "Password must be 6 to 64 characters." });
    if (referralCode && !/^[A-F0-9]{10}$/.test(referralCode)) return res.status(400).json({ success: false, message: "Invalid invite code." });

    let referrer = null;
    if (referralCode) {
        referrer = await User.findOne({ referral_code: referralCode });
        if (!referrer) return res.status(400).json({ success: false, message: "This invite code is not valid." });
    }

    const existing = await User.findOne({ phone });
    if (existing) return res.status(409).json({ success: false, message: "An account with this mobile number already exists." });

    const passwordHash = await bcrypt.hash(password, 12);
    await User.create({
        name, phone, password_hash: passwordHash,
        referral_code: await createReferralCode(),
        referred_by_user_id: referrer ? referrer._id : null
    });

    res.status(201).json({ success: true, message: "Account created successfully." });
}));

app.post("/api/login", authLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const phone = typeof req.body.phone === "string" ? req.body.phone : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";

    if (!/^\d{10}$/.test(phone) || !password || password.length > 64) {
        return res.status(400).json({ success: false, message: "Enter a valid mobile number and password." });
    }

    const user = await User.findOne({ phone });
    const passwordMatches = user
        ? await bcrypt.compare(password, user.password_hash)
        : await bcrypt.compare(password, "$2a$12$invalidsaltinvalidsaltinvalidsaltinvalidsaltinv");

    if (!user || user.status !== "active" || !passwordMatches) {
        return res.status(401).json({ success: false, message: "Invalid mobile number or password." });
    }

    await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
    req.session.user = { id: user._id.toString(), name: user.name, phone: user.phone };
    req.session.csrfToken = createCsrfToken();
    await new Promise((resolve, reject) => req.session.save(e => e ? reject(e) : resolve()));

    res.json({ success: true, message: "Login successful.", csrfToken: req.session.csrfToken });
}));

app.get("/api/session", asyncRoute(async (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!req.session.user) return res.status(401).json({ success: false, message: "Not logged in." });
    const user = await User.findById(req.session.user.id);
    if (!user || user.status !== "active") return res.status(401).json({ success: false, message: "This account is unavailable." });
    res.json({
        success: true,
        user: {
            id: user._id.toString(), name: user.name, phone: user.phone, status: user.status,
            balancePaise: user.balance_paise, referralCode: user.referral_code
        }
    });
}));

app.post("/api/logout", requireCsrf, asyncRoute(async (req, res) => {
    await new Promise((resolve, reject) => req.session.destroy(e => e ? reject(e) : resolve()));
    res.clearCookie("kingfisher.sid", { httpOnly: true, secure: isProduction, sameSite: "strict" });
    res.json({ success: true, message: "Logged out." });
}));

// ========== WALLET & TRANSACTIONS ==========
app.get("/api/wallet", requireAuth, asyncRoute(async (req, res) => {
    const userId = req.session.user.id;
    const user = await User.findById(userId);
    const pendingWithdrawals = await WalletTransaction.aggregate([
        { $match: { user_id: user._id, type: "withdrawal", status: { $in: ["pending", "processing"] } } },
        { $group: { _id: null, total: { $sum: "$amount_paise" } } }
    ]);
    const pendingWithdrawalsPaise = pendingWithdrawals[0]?.total || 0;

    const transactions = await WalletTransaction.find({ user_id: userId }).sort({ createdAt: -1 }).limit(100);

    const bankAccount = await BankAccount.findOne({ user_id: userId });
    const minimumRecharge = Number((await SiteSetting.findOne({ key: "minimum_recharge_rupees" }))?.value || 295);
    const minimumWithdrawal = Number((await SiteSetting.findOne({ key: "minimum_withdrawal_rupees" }))?.value || 170);

    const approvedRecharges = await WalletTransaction.aggregate([
        { $match: { user_id: user._id, type: "recharge", status: "approved" } },
        { $group: { _id: null, total: { $sum: "$amount_paise" } } }
    ]);
    const approvedRewards = await WalletTransaction.aggregate([
        { $match: { user_id: user._id, type: "adjustment", status: "approved", amount_paise: { $gt: 0 } } },
        { $group: { _id: null, total: { $sum: "$amount_paise" } } }
    ]);

    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        balancePaise: user.balance_paise,
        pendingWithdrawalsPaise,
        approvedRechargesPaise: approvedRecharges[0]?.total || 0,
        approvedRewardsPaise: approvedRewards[0]?.total || 0,
        bankAccount: bankAccount ? { accountLast4: bankAccount.account_last4, ifsc: bankAccount.ifsc } : null,
        minimumRecharge, minimumWithdrawal,
        transactions: transactions.map(t => ({
            id: t._id.toString(), type: t.type, amountPaise: t.amount_paise, status: t.status,
            reference: t.reference, note: t.note, createdAt: t.createdAt, reviewedAt: t.reviewed_at
        })),
        requests: []
    });
}));

// ========== RECHARGE ==========
app.post("/api/recharge", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const amountPaise = parseRupees(req.body.amount);
    const method = typeof req.body.method === "string" ? req.body.method.trim().slice(0, 40) : "";
    const minimum = Number((await SiteSetting.findOne({ key: "minimum_recharge_rupees" }))?.value || 295);
    if (!amountPaise || amountPaise < minimum * 100 || !method) {
        return res.status(400).json({ success: false, message: "Enter a valid amount and payment channel." });
    }
    const result = await WalletTransaction.create({
        user_id: req.session.user.id, type: "recharge", amount_paise: amountPaise,
        status: "pending", reference: method, note: "Submitted for manual verification"
    });
    res.status(202).json({
        success: true, transactionId: result._id.toString(),
        message: "Recharge request submitted for admin review. No balance has been credited yet."
    });
}));

// ========== WITHDRAWAL ==========
app.post("/api/withdrawal", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const amountPaise = parseRupees(req.body.amount);
    const minimum = Number((await SiteSetting.findOne({ key: "minimum_withdrawal_rupees" }))?.value || 170);
    if (!amountPaise || amountPaise < minimum * 100) {
        return res.status(400).json({ success: false, message: "Enter a valid withdrawal amount." });
    }
    const bankAccount = await BankAccount.findOne({ user_id: req.session.user.id });
    if (!bankAccount) return res.status(400).json({ success: false, message: "Save your bank account in Bank setup before requesting a withdrawal." });

    const user = await User.findById(req.session.user.id);
    const pendingTotal = await WalletTransaction.aggregate([
        { $match: { user_id: user._id, type: "withdrawal", status: { $in: ["pending", "processing"] } } },
        { $group: { _id: null, total: { $sum: "$amount_paise" } } }
    ]);
    const pending = pendingTotal[0]?.total || 0;
    if (amountPaise + pending > user.balance_paise) {
        return res.status(400).json({ success: false, message: "Amount exceeds your available balance." });
    }

    const result = await WalletTransaction.create({
        user_id: req.session.user.id, type: "withdrawal", amount_paise: amountPaise,
        status: "pending", reference: `withdrawal-${Date.now()}`, note: "Awaiting payout review"
    });
    res.status(202).json({
        success: true, transactionId: result._id.toString(),
        message: "Withdrawal request submitted for admin review. No payout has been sent yet."
    });
}));

// ========== BANK ACCOUNT ==========
app.get("/api/bank-account", requireAuth, asyncRoute(async (req, res) => {
    const account = await BankAccount.findOne({ user_id: req.session.user.id });
    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        account: account ? {
            holderName: account.holder_name, bankName: account.bank_name,
            accountLast4: account.account_last4, ifsc: account.ifsc, updatedAt: account.updatedAt
        } : null
    });
}));

app.put("/api/bank-account", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const holderName = typeof req.body.holderName === "string" ? req.body.holderName.trim() : "";
    const bankName = typeof req.body.bankName === "string" ? req.body.bankName.trim() : "";
    const accountNumber = typeof req.body.accountNumber === "string" ? req.body.accountNumber.replace(/\s+/g, "") : "";
    const ifsc = typeof req.body.ifsc === "string" ? req.body.ifsc.trim().toUpperCase() : "";

    if (!holderName || holderName.length > 80 || !bankName || bankName.length > 80
        || !/^\d{8,18}$/.test(accountNumber) || !/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)) {
        return res.status(400).json({ success: false, message: "Enter a valid account holder, bank, 8–18 digit account number and IFSC code." });
    }

    const pendingWithdrawal = await WalletTransaction.findOne({
        user_id: req.session.user.id, type: "withdrawal", status: { $in: ["pending", "processing"] }
    });
    if (pendingWithdrawal) return res.status(409).json({ success: false, message: "Bank details cannot be changed while a withdrawal is pending." });

    const encrypted = encryptBankAccount(accountNumber);
    await BankAccount.findOneAndUpdate(
        { user_id: req.session.user.id },
        {
            holder_name: holderName, bank_name: bankName,
            account_ciphertext: encrypted.ciphertext,
            account_iv: encrypted.iv, account_tag: encrypted.tag,
            account_last4: accountNumber.slice(-4), ifsc
        },
        { upsert: true, new: true }
    );
    res.json({
        success: true,
        account: { holderName, bankName, accountLast4: accountNumber.slice(-4), ifsc },
        message: "Bank details saved encrypted. Only the last four account digits are shown in your profile."
    });
}));

// ========== PRODUCTS ==========
app.get("/api/products", requireAuth, asyncRoute(async (req, res) => {
    const products = await Product.find({ active: true }).sort({ category: 1, createdAt: 1 });
    const purchasedCounts = await UserProduct.aggregate([
        { $match: { user_id: new mongoose.Types.ObjectId(req.session.user.id) } },
        { $group: { _id: "$product_id", count: { $sum: 1 } } }
    ]);
    const countMap = Object.fromEntries(purchasedCounts.map(p => [p._id.toString(), p.count]));

    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        products: products.map(p => ({
            id: p._id.toString(), name: p.name, category: p.category,
            pricePaise: p.price_paise, durationDays: p.duration_days,
            dailyRewardPaise: p.daily_reward_paise, totalRewardPaise: p.total_reward_paise,
            purchaseLimit: p.purchase_limit, imageUrl: p.image_url,
            purchasedCount: countMap[p._id.toString()] || 0
        }))
    });
}));

app.post("/api/products/purchase", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const productId = req.body.productId;
    if (!mongoose.Types.ObjectId.isValid(productId)) {
        return res.status(400).json({ success: false, message: "Choose a valid product." });
    }
    const product = await Product.findOne({ _id: productId, active: true });
    if (!product) return res.status(404).json({ success: false, message: "This product is no longer available." });

    const purchasedCount = await UserProduct.countDocuments({ user_id: req.session.user.id, product_id: productId });
    if (purchasedCount >= product.purchase_limit) {
        return res.status(409).json({ success: false, message: "You have reached the purchase limit for this product." });
    }

    const user = await User.findById(req.session.user.id);
    const pendingAgg = await WalletTransaction.aggregate([
        { $match: { user_id: user._id, type: "withdrawal", status: { $in: ["pending", "processing"] } } },
        { $group: { _id: null, total: { $sum: "$amount_paise" } } }
    ]);
    const pending = pendingAgg[0]?.total || 0;
    const availablePaise = user.balance_paise - pending;

    if (availablePaise < product.price_paise) {
        return res.status(400).json({ success: false, message: "Insufficient available wallet balance. Complete a verified recharge first." });
    }

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + product.duration_days);

    const purchase = await UserProduct.create({
        user_id: user._id, product_id: product._id, product_name: product.name,
        price_paise: product.price_paise, duration_days: product.duration_days,
        expires_at: expiresAt, status: "active"
    });

    if (product.price_paise > 0) {
        user.balance_paise -= product.price_paise;
        await user.save();
        await WalletTransaction.create({
            user_id: user._id, type: "adjustment", amount_paise: -product.price_paise,
            status: "approved", note: `Product purchase #${purchase._id}: ${product.name}`,
            reviewed_at: new Date()
        });
    }

    res.status(201).json({
        success: true, purchaseId: purchase._id.toString(),
        productName: product.name, pricePaise: product.price_paise,
        message: `${product.name} is active. ₹${(product.price_paise / 100).toFixed(2)} was deducted from the internal wallet.`
    });
}));

app.get("/api/my-products", requireAuth, asyncRoute(async (req, res) => {
    const products = await UserProduct.find({ user_id: req.session.user.id }).sort({ createdAt: -1 }).limit(100);
    const productIds = products.map(p => p.product_id);
    const productDocs = await Product.find({ _id: { $in: productIds } });
    const imageMap = Object.fromEntries(productDocs.map(p => [p._id.toString(), p.image_url]));

    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        products: products.map(p => ({
            id: p._id.toString(), productId: p.product_id.toString(), productName: p.product_name,
            pricePaise: p.price_paise, durationDays: p.duration_days,
            purchasedAt: p.purchased_at, expiresAt: p.expires_at,
            status: p.expires_at <= new Date() ? "expired" : p.status,
            imageUrl: imageMap[p.product_id.toString()] || ""
        }))
    });
}));

// ========== TEAM ==========
app.get("/api/team", requireAuth, asyncRoute(async (req, res) => {
    const userId = req.session.user.id;

    const level1 = await User.find({ referred_by_user_id: userId }).select("_id status");
    const l1ids = level1.map(u => u._id);
    const level2 = await User.find({ referred_by_user_id: { $in: l1ids } }).select("_id status");
    const l2ids = level2.map(u => u._id);
    const level3 = await User.find({ referred_by_user_id: { $in: l2ids } }).select("_id status");

    const user = await User.findById(userId);

    const levels = [
        { level: 1, members: level1 },
        { level: 2, members: level2 },
        { level: 3, members: level3 }
    ].map(l => ({
        level: l.level,
        total: l.members.length,
        active: l.members.filter(m => m.status === "active").length,
        rechargePaise: 0
    }));

    res.set("Cache-Control", "no-store");
    res.json({
        success: true, referralCode: user.referral_code,
        totalMembers: levels.reduce((s, r) => s + r.total, 0),
        activeMembers: levels.reduce((s, r) => s + r.active, 0),
        totalRechargePaise: 0, levels, commissionPaise: 0
    });
}));

// ========== MISSIONS ==========
app.get("/api/missions", requireAuth, asyncRoute(async (req, res) => {
    const activeMembers = await countActiveTeamMembers(req.session.user.id);
    const missions = await Mission.find({ active: true }).sort({ target_members: 1 });
    const claims = await MissionClaim.find({ user_id: req.session.user.id });
    const claimMap = Object.fromEntries(claims.map(c => [c.mission_id.toString(), c.status]));

    res.json({
        success: true, activeMembers,
        missions: missions.map(m => ({
            id: m._id.toString(), name: m.name, description: m.description,
            targetMembers: m.target_members, rewardPaise: m.reward_paise,
            claimStatus: claimMap[m._id.toString()] || null
        }))
    });
}));

app.post("/api/missions/claim", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const missionId = req.body.missionId;
    if (!mongoose.Types.ObjectId.isValid(missionId)) {
        return res.status(400).json({ success: false, message: "Choose a valid mission." });
    }
    const mission = await Mission.findOne({ _id: missionId, active: true });
    if (!mission) return res.status(404).json({ success: false, message: "Mission not found." });

    const activeMembers = await countActiveTeamMembers(req.session.user.id);
    if (activeMembers < mission.target_members) {
        return res.status(400).json({ success: false, message: "Your verified team has not reached this mission yet." });
    }

    const existing = await MissionClaim.findOne({ user_id: req.session.user.id, mission_id: missionId });
    if (existing && existing.status !== "rejected") {
        return res.status(409).json({
            success: false,
            message: existing.status === "approved" ? "This mission reward was already approved." : "This mission is already waiting for review."
        });
    }
    if (existing) {
        existing.status = "pending"; existing.note = ""; existing.reviewed_by_admin_id = null;
        existing.reviewed_at = null; await existing.save();
    } else {
        await MissionClaim.create({ user_id: req.session.user.id, mission_id: missionId, status: "pending" });
    }
    res.status(202).json({ success: true, message: "Mission claim submitted for admin verification." });
}));

app.post("/api/spin", requireCsrf, requireAuth, (req, res) => {
    res.status(503).json({ success: false, message: "Prize spins are not configured. No spin or reward was used." });
}); // ========== ADMIN ROUTES ==========
app.get("/api/admin/session", asyncRoute(async (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!req.session.admin || req.session.impersonation) {
        const adminCount = await Admin.countDocuments();
        return res.status(401).json({ success: false, configured: adminCount > 0 });
    }
    const admin = await Admin.findById(req.session.admin.id);
    if (!admin) return res.status(401).json({ success: false });
    res.json({
        success: true,
        admin: { username: admin.username, passwordChangeRequired: admin.password_change_required },
        csrfToken: req.session.csrfToken
    });
}));

app.post("/api/admin/login", adminLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const admin = await Admin.findOne({ username: { $regex: `^${username}$`, $options: "i" } });
    const passwordMatches = admin
        ? await bcrypt.compare(password, admin.password_hash)
        : await bcrypt.compare(password, "$2a$12$invalidsaltinvalidsaltinvalidsaltinvalidsaltinv");
    if (!admin || !passwordMatches || !password) {
        return res.status(401).json({ success: false, message: "Invalid admin username or password." });
    }
    await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
    req.session.admin = { id: admin._id.toString(), username: admin.username };
    req.session.csrfToken = createCsrfToken();
    await new Promise((resolve, reject) => req.session.save(e => e ? reject(e) : resolve()));
    admin.last_login_at = new Date();
    await admin.save();
    await auditAdmin(admin._id, "login", "admin", admin._id, {});
    res.json({
        success: true,
        admin: { username: admin.username, passwordChangeRequired: admin.password_change_required },
        csrfToken: req.session.csrfToken
    });
}));

app.post("/api/admin/logout", requireCsrf, requireAdmin, asyncRoute(async (req, res) => {
    await auditAdmin(req.session.admin.id, "logout", "admin", req.session.admin.id, {});
    await new Promise((resolve, reject) => req.session.destroy(e => e ? reject(e) : resolve()));
    res.clearCookie("kingfisher.sid", { httpOnly: true, secure: isProduction, sameSite: "strict" });
    res.json({ success: true });
}));

app.post("/api/admin/change-password", requireCsrf, requireAdmin, asyncRoute(async (req, res) => {
    const currentPassword = typeof req.body.currentPassword === "string" ? req.body.currentPassword : "";
    const newPassword = typeof req.body.newPassword === "string" ? req.body.newPassword : "";
    const admin = await Admin.findById(req.session.admin.id);
    if (!admin || !(await bcrypt.compare(currentPassword, admin.password_hash))) {
        return res.status(400).json({ success: false, message: "Current password is incorrect." });
    }
    if (newPassword.length < 12 || newPassword.length > 128) {
        return res.status(400).json({ success: false, message: "New password must be 12 to 128 characters." });
    }
    admin.password_hash = await bcrypt.hash(newPassword, 12);
    admin.password_change_required = false;
    await admin.save();
    await auditAdmin(req.session.admin.id, "change_password", "admin", req.session.admin.id, {});
    res.json({ success: true, message: "Admin password updated." });
}));

// Admin middleware — GET allow, baaki sab CSRF + Auth
app.use("/api/admin", (req, res, next) => {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
    requireCsrf(req, res, next);
}, requireAdmin);

// ========== ADMIN OVERVIEW ==========
app.get("/api/admin/overview", requireAdmin, asyncRoute(async (req, res) => {
    const [users, activeUsers, suspendedUsers, walletAgg, pendingTx, pendingClaims, pendingReq, activeProducts, activeMissions] = await Promise.all([
        User.countDocuments(),
        User.countDocuments({ status: "active" }),
        User.countDocuments({ status: "suspended" }),
        User.aggregate([{ $group: { _id: null, total: { $sum: "$balance_paise" } } }]),
        WalletTransaction.countDocuments({ status: { $in: ["pending", "processing"] } }),
        MissionClaim.countDocuments({ status: "pending" }),
        ProductRequest.countDocuments({ status: "pending" }),
        Product.countDocuments({ active: true }),
        Mission.countDocuments({ active: true })
    ]);
    res.json({
        success: true,
        summary: {
            users, activeUsers, suspendedUsers,
            walletPaise: walletAgg[0]?.total || 0,
            pendingTransactions: pendingTx, pendingMissionClaims: pendingClaims,
            pendingProductRequests: pendingReq, activeProducts, activeMissions
        }
    });
}));

// ========== ADMIN USERS ==========
app.get("/api/admin/users", requireAdmin, asyncRoute(async (req, res) => {
    const search = typeof req.query.search === "string" ? req.query.search.trim().slice(0, 80) : "";
    const page = Math.max(1, Math.min(10000, Number.parseInt(req.query.page, 10) || 1));
    const limit = 25;
    const filter = search ? {
        $or: [
            { name: { $regex: search, $options: "i" } },
            { phone: { $regex: search, $options: "i" } }
        ]
    } : {};
    const [users, total] = await Promise.all([
        User.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit),
        User.countDocuments(filter)
    ]);
    res.json({
        success: true, total, page, pageSize: limit,
        users: users.map(u => ({
            id: u._id.toString(), name: u.name, phone: u.phone, status: u.status,
            balancePaise: u.balance_paise, createdAt: u.createdAt, bankConfigured: false
        }))
    });
}));

app.patch("/api/admin/users/:id/status", requireAdmin, asyncRoute(async (req, res) => {
    const status = req.body.status;
    if (!["active", "suspended"].includes(status)) {
        return res.status(400).json({ success: false, message: "Invalid user status." });
    }
    const user = await User.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!user) return res.status(404).json({ success: false, message: "User not found." });
    await auditAdmin(req.session.admin.id, "set_user_status", "user", req.params.id, { status });
    res.json({ success: true });
}));

app.post("/api/admin/users/:id/reset-password", requireAdmin, asyncRoute(async (req, res) => {
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (password.length < 8 || password.length > 128) {
        return res.status(400).json({ success: false, message: "User password must be 8 to 128 characters." });
    }
    const hash = await bcrypt.hash(password, 12);
    const user = await User.findByIdAndUpdate(req.params.id, { password_hash: hash }, { new: true });
    if (!user) return res.status(404).json({ success: false, message: "User not found." });
    await auditAdmin(req.session.admin.id, "reset_user_password", "user", req.params.id, {});
    res.json({ success: true, message: "User password reset. Share the temporary password securely." });
}));

app.post("/api/admin/users/:id/adjust-balance", requireAdmin, asyncRoute(async (req, res) => {
    const amountPaise = parseRupees(req.body.amount);
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!amountPaise || !note) return res.status(400).json({ success: false, message: "Enter a valid non-zero amount and reason." });
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });
    if (user.balance_paise + amountPaise < 0) {
        return res.status(400).json({ success: false, message: "Adjustment would make the wallet negative." });
    }
    user.balance_paise += amountPaise;
    await user.save();
    await WalletTransaction.create({
        user_id: user._id, type: "adjustment", amount_paise: amountPaise,
        status: "approved", note,
        created_by_admin_id: req.session.admin.id,
        reviewed_by_admin_id: req.session.admin.id, reviewed_at: new Date()
    });
    await auditAdmin(req.session.admin.id, "adjust_wallet", "user", req.params.id, { amountPaise, note });
    res.json({ success: true, balancePaise: user.balance_paise });
}));

// ========== ADMIN TRANSACTIONS ==========
app.get("/api/admin/transactions", requireAdmin, asyncRoute(async (req, res) => {
    const status = typeof req.query.status === "string" ? req.query.status : "";
    const validStatus = ["pending", "processing", "approved", "rejected"].includes(status) ? status : "";
    const filter = validStatus ? { status: validStatus } : {};
    const transactions = await WalletTransaction.find(filter)
        .sort({ status: 1, createdAt: -1 }).limit(300).populate("user_id", "name phone");
    res.json({
        success: true,
        transactions: transactions.map(t => ({
            id: t._id.toString(), userId: t.user_id?._id?.toString() || "",
            userName: t.user_id?.name || "Unknown", phone: t.user_id?.phone || "",
            type: t.type, amountPaise: t.amount_paise, status: t.status,
            reference: t.reference, note: t.note,
            createdAt: t.createdAt, reviewedAt: t.reviewed_at
        }))
    });
}));

app.post("/api/admin/transactions/:id/review", requireAdmin, asyncRoute(async (req, res) => {
    const decision = req.body.decision;
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!["processing", "approved", "rejected"].includes(decision) || !note) {
        return res.status(400).json({ success: false, message: "Choose a valid decision and enter a review note." });
    }
    const transaction = await WalletTransaction.findById(req.params.id);
    if (!transaction) return res.status(404).json({ success: false, message: "Transaction not found." });

    if (decision === "processing") {
        if (transaction.type !== "withdrawal" || transaction.status !== "pending") {
            return res.status(409).json({ success: false, message: "Only pending withdrawal requests can be moved to processing." });
        }
    } else if (!["pending", "processing"].includes(transaction.status)) {
        return res.status(409).json({ success: false, message: "This transaction has already been reviewed." });
    }

    if (decision === "approved" && transaction.type === "withdrawal") {
        const user = await User.findById(transaction.user_id);
        if (user.balance_paise < transaction.amount_paise) {
            return res.status(409).json({ success: false, message: "Insufficient available balance for this withdrawal." });
        }
        user.balance_paise -= transaction.amount_paise;
        await user.save();
    } else if (decision === "approved" && transaction.type === "recharge") {
        await User.findByIdAndUpdate(transaction.user_id, { $inc: { balance_paise: transaction.amount_paise } });
    }

    transaction.status = decision;
    transaction.note = note;
    transaction.reviewed_by_admin_id = req.session.admin.id;
    transaction.reviewed_at = new Date();
    await transaction.save();
    await auditAdmin(req.session.admin.id, `transaction_${decision}`, "transaction", req.params.id, { note });
    res.json({ success: true });
}));

app.post("/api/admin/transactions", requireAdmin, asyncRoute(async (req, res) => {
    const userId = req.body.userId;
    const type = req.body.type;
    const amountPaise = parseRupees(req.body.amount);
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    const reference = typeof req.body.reference === "string" ? req.body.reference.trim().slice(0, 120) : "";
    if (!mongoose.Types.ObjectId.isValid(userId) || !["recharge", "withdrawal"].includes(type) || !amountPaise || amountPaise < 0 || !note) {
        return res.status(400).json({ success: false, message: "Check transaction fields and try again." });
    }
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });
    const tx = await WalletTransaction.create({
        user_id: userId, type, amount_paise: amountPaise,
        status: "pending", reference, note,
        created_by_admin_id: req.session.admin.id
    });
    await auditAdmin(req.session.admin.id, "create_transaction", "transaction", tx._id, { userId, type, amountPaise });
    res.status(201).json({ success: true, id: tx._id.toString() });
}));

// ========== ADMIN PRODUCTS ==========
app.get("/api/admin/products", requireAdmin, asyncRoute(async (req, res) => {
    const products = await Product.find().sort({ category: 1, createdAt: 1 });
    res.json({
        success: true,
        products: products.map(p => ({
            id: p._id.toString(), name: p.name, category: p.category,
            pricePaise: p.price_paise, durationDays: p.duration_days,
            dailyRewardPaise: p.daily_reward_paise, totalRewardPaise: p.total_reward_paise,
            purchaseLimit: p.purchase_limit, active: p.active, imageUrl: p.image_url
        }))
    });
}));

app.post("/api/admin/products", requireAdmin, asyncRoute(async (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim().slice(0, 80) : "";
    const category = req.body.category;
    const pricePaise = parseRupees(req.body.price);
    const durationDays = Number(req.body.durationDays);
    const dailyRewardPaise = parseRupees(req.body.dailyReward || 0);
    const totalRewardPaise = parseRupees(req.body.totalReward || 0);
    const purchaseLimit = Number(req.body.purchaseLimit);
    const imageUrl = typeof req.body.imageUrl === "string" ? req.body.imageUrl.trim() : "";
    if (!name || !["daily", "vip"].includes(category) || pricePaise === null || pricePaise < 0
        || !Number.isInteger(durationDays) || durationDays < 1 || durationDays > 3650
        || dailyRewardPaise === null || totalRewardPaise === null
        || !Number.isInteger(purchaseLimit) || purchaseLimit < 1 || purchaseLimit > 10000
        || (imageUrl && !/^\/uploads\/media\/[a-f0-9]{32}\.(?:png|jpg|webp)$/.test(imageUrl))) {
        return res.status(400).json({ success: false, message: "Check product fields and try again." });
    }
    const product = await Product.create({
        name, category, price_paise: pricePaise, duration_days: durationDays,
        daily_reward_paise: dailyRewardPaise, total_reward_paise: totalRewardPaise,
        purchase_limit: purchaseLimit, image_url: imageUrl
    });
    await auditAdmin(req.session.admin.id, "create_product", "product", product._id, { name });
    res.status(201).json({ success: true, id: product._id.toString() });
}));

app.put("/api/admin/products/:id", requireAdmin, asyncRoute(async (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim().slice(0, 80) : "";
    const category = req.body.category;
    const pricePaise = parseRupees(req.body.price);
    const durationDays = Number(req.body.durationDays);
    const dailyRewardPaise = parseRupees(req.body.dailyReward || 0);
    const totalRewardPaise = parseRupees(req.body.totalReward || 0);
    const purchaseLimit = Number(req.body.purchaseLimit);
    const imageUrl = typeof req.body.imageUrl === "string" ? req.body.imageUrl.trim() : "";
    const active = req.body.active === false || req.body.active === 0 ? false : true;
    if (!name || !["daily", "vip"].includes(category) || pricePaise === null
        || !Number.isInteger(durationDays) || durationDays < 1
        || !Number.isInteger(purchaseLimit) || purchaseLimit < 1) {
        return res.status(400).json({ success: false, message: "Check product fields and try again." });
    }
    const product = await Product.findByIdAndUpdate(req.params.id, {
        name, category, price_paise: pricePaise, duration_days: durationDays,
        daily_reward_paise: dailyRewardPaise, total_reward_paise: totalRewardPaise,
        purchase_limit: purchaseLimit, image_url: imageUrl, active
    }, { new: true });
    if (!product) return res.status(404).json({ success: false, message: "Product not found." });
    await auditAdmin(req.session.admin.id, "update_product", "product", req.params.id, { name, active });
    res.json({ success: true });
}));

app.delete("/api/admin/products/:id", requireAdmin, asyncRoute(async (req, res) => {
    const product = await Product.findByIdAndUpdate(req.params.id, { active: false }, { new: true });
    if (!product) return res.status(404).json({ success: false, message: "Product not found." });
    await auditAdmin(req.session.admin.id, "deactivate_product", "product", req.params.id, {});
    res.json({ success: true });
}));

// ========== ADMIN MISSIONS ==========
app.get("/api/admin/missions", requireAdmin, asyncRoute(async (req, res) => {
    const missions = await Mission.find().sort({ target_members: 1 });
    res.json({
        success: true,
        missions: missions.map(m => ({
            id: m._id.toString(), name: m.name, description: m.description,
            targetMembers: m.target_members, rewardPaise: m.reward_paise, active: m.active
        }))
    });
}));

app.post("/api/admin/missions", requireAdmin, asyncRoute(async (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim().slice(0, 100) : "";
    const description = typeof req.body.description === "string" ? req.body.description.trim().slice(0, 500) : "";
    const targetMembers = Number(req.body.targetMembers);
    const rewardPaise = parseRupees(req.body.reward);
    if (!name || !Number.isInteger(targetMembers) || targetMembers < 0 || rewardPaise === null || rewardPaise < 0) {
        return res.status(400).json({ success: false, message: "Check mission fields and try again." });
    }
    const mission = await Mission.create({ name, description, target_members: targetMembers, reward_paise: rewardPaise });
    await auditAdmin(req.session.admin.id, "create_mission", "mission", mission._id, { name });
    res.status(201).json({ success: true, id: mission._id.toString() });
}));

app.put("/api/admin/missions/:id", requireAdmin, asyncRoute(async (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim().slice(0, 100) : "";
    const description = typeof req.body.description === "string" ? req.body.description.trim().slice(0, 500) : "";
    const targetMembers = Number(req.body.targetMembers);
    const rewardPaise = parseRupees(req.body.reward);
    const active = req.body.active === false || req.body.active === 0 ? false : true;
    if (!name || !Number.isInteger(targetMembers) || targetMembers < 0 || rewardPaise === null || rewardPaise < 0) {
        return res.status(400).json({ success: false, message: "Check mission fields and try again." });
    }
    const mission = await Mission.findByIdAndUpdate(req.params.id, {
        name, description, target_members: targetMembers, reward_paise: rewardPaise, active
    }, { new: true });
    if (!mission) return res.status(404).json({ success: false, message: "Mission not found." });
    await auditAdmin(req.session.admin.id, "update_mission", "mission", req.params.id, { name, active });
    res.json({ success: true });
}));

// ========== ADMIN MISSION CLAIMS ==========
app.get("/api/admin/mission-claims", requireAdmin, asyncRoute(async (req, res) => {
    const status = typeof req.query.status === "string" && ["pending", "approved", "rejected"].includes(req.query.status) ? req.query.status : "";
    const filter = status ? { status } : {};
    const claims = await MissionClaim.find(filter).sort({ createdAt: -1 }).limit(300).populate("user_id", "name phone").populate("mission_id", "name target_members reward_paise");
    res.json({
        success: true,
        claims: claims.map(c => ({
            id: c._id.toString(), userId: c.user_id?._id?.toString() || "",
            userName: c.user_id?.name || "", phone: c.user_id?.phone || "",
            missionId: c.mission_id?._id?.toString() || "", missionName: c.mission_id?.name || "",
            targetMembers: c.mission_id?.target_members || 0, rewardPaise: c.mission_id?.reward_paise || 0,
            status: c.status, note: c.note, createdAt: c.createdAt, reviewedAt: c.reviewed_at
        }))
    });
}));

app.post("/api/admin/mission-claims/:id/review", requireAdmin, asyncRoute(async (req, res) => {
    const decision = req.body.decision;
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!["approved", "rejected"].includes(decision) || !note) {
        return res.status(400).json({ success: false, message: "Choose a decision and enter a review note." });
    }
    const claim = await MissionClaim.findById(req.params.id);
    if (!claim) return res.status(404).json({ success: false, message: "Mission claim not found." });
    if (claim.status !== "pending") return res.status(409).json({ success: false, message: "This claim has already been reviewed." });

    if (decision === "approved") {
        const mission = await Mission.findById(claim.mission_id);
        const activeMembers = await countActiveTeamMembers(claim.user_id.toString());
        if (!mission || !mission.active || activeMembers < mission.target_members) {
            return res.status(409).json({ success: false, message: "The mission is inactive or the member no longer meets its team requirement." });
        }
        await User.findByIdAndUpdate(claim.user_id, { $inc: { balance_paise: mission.reward_paise } });
        if (mission.reward_paise > 0) {
            await WalletTransaction.create({
                user_id: claim.user_id, type: "adjustment", amount_paise: mission.reward_paise,
                status: "approved", note: `Mission claim #${claim._id}: ${note}`,
                created_by_admin_id: req.session.admin.id,
                reviewed_by_admin_id: req.session.admin.id, reviewed_at: new Date()
            });
        }
    }
    claim.status = decision;
    claim.note = note;
    claim.reviewed_by_admin_id = req.session.admin.id;
    claim.reviewed_at = new Date();
    await claim.save();
    await auditAdmin(req.session.admin.id, `mission_claim_${decision}`, "mission_claim", req.params.id, { note });
    res.json({ success: true });
}));

// ========== ADMIN DEMO ACCOUNTS ==========
app.get("/api/admin/demo-accounts", requireAdmin, asyncRoute(async (req, res) => {
    const accounts = await DemoAccount.find().sort({ createdAt: -1 }).limit(200);
    const transactions = await DemoWalletTransaction.find().sort({ createdAt: -1 }).limit(200).populate("demo_account_id", "demo_code name");
    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        accounts: accounts.map(a => ({
            id: a._id.toString(), demoCode: a.demo_code, name: a.name,
            balancePaise: a.balance_paise, createdAt: a.createdAt
        })),
        transactions: transactions.map(t => ({
            id: t._id.toString(), demoAccountId: t.demo_account_id?._id?.toString() || "",
            demoCode: t.demo_account_id?.demo_code || "", accountName: t.demo_account_id?.name || "",
            type: t.type, amountPaise: t.amount_paise, note: t.note, createdAt: t.createdAt
        }))
    });
}));

app.post("/api/admin/demo-accounts", requireAdmin, asyncRoute(async (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    if (!name || name.length > 80) return res.status(400).json({ success: false, message: "Enter a demo account name up to 80 characters." });
    let demoCode;
    do { demoCode = `DEMO-${randomBytes(4).toString("hex").toUpperCase()}`; }
    while (await DemoAccount.findOne({ demo_code: demoCode }));
    const account = await DemoAccount.create({ demo_code: demoCode, name, created_by_admin_id: req.session.admin.id });
    await auditAdmin(req.session.admin.id, "create_demo_account", "demo_account", account._id, { demoCode, name });
    res.status(201).json({
        success: true,
        account: { id: account._id.toString(), demoCode, name, balancePaise: 0 },
        message: "Demo account created. It is separate from real users and cannot receive or send real money."
    });
}));

app.post("/api/admin/demo-accounts/:id/transactions", requireAdmin, asyncRoute(async (req, res) => {
    const type = req.body.type;
    const amountPaise = parseRupees(req.body.amount);
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!["deposit", "withdrawal"].includes(type) || !Number.isSafeInteger(amountPaise) || amountPaise <= 0 || !note) {
        return res.status(400).json({ success: false, message: "Enter a valid demo account, transaction type, amount and note." });
    }
    const account = await DemoAccount.findById(req.params.id);
    if (!account) return res.status(404).json({ success: false, message: "Demo account not found." });
    if (type === "withdrawal" && account.balance_paise < amountPaise) {
        return res.status(400).json({ success: false, message: "Demo withdrawal exceeds the demo balance." });
    }
    account.balance_paise += type === "deposit" ? amountPaise : -amountPaise;
    await account.save();
    await DemoWalletTransaction.create({
        demo_account_id: account._id,
        type: type === "deposit" ? "demo_deposit" : "demo_withdrawal",
        amount_paise: amountPaise, note, created_by_admin_id: req.session.admin.id
    });
    await auditAdmin(req.session.admin.id, `demo_${type}`, "demo_account", account._id, { amountPaise, note });
    res.status(201).json({
        success: true, balancePaise: account.balance_paise,
        message: `Simulated demo ${type} recorded. No real wallet or payment was changed.`
    });
}));

// ========== ADMIN SETTINGS ==========
app.get("/api/admin/settings", requireAdmin, asyncRoute(async (req, res) => {
    const settings = await SiteSetting.find().sort({ key: 1 });
    res.json({ success: true, settings: settings.map(s => ({ key: s.key, value: s.value, updatedAt: s.updatedAt })) });
}));

app.put("/api/admin/settings/:key", requireAdmin, asyncRoute(async (req, res) => {
    const key = req.params.key;
    const value = typeof req.body.value === "string" ? req.body.value.trim() : "";
    if (!/^[a-z][a-z0-9_]{1,63}$/.test(key) || value.length > 500) {
        return res.status(400).json({ success: false, message: "Invalid setting key or value." });
    }
    await SiteSetting.findOneAndUpdate(
        { key }, { value, updated_by_admin_id: req.session.admin.id },
        { upsert: true, new: true }
    );
    await auditAdmin(req.session.admin.id, "update_setting", "setting", key, { value });
    res.json({ success: true });
}));

// ========== ADMIN AUDIT ==========
app.get("/api/admin/audit", requireAdmin, asyncRoute(async (req, res) => {
    const events = await AdminAudit.find().sort({ createdAt: -1 }).limit(200).populate("admin_id", "username");
    res.json({
        success: true,
        events: events.map(e => ({
            id: e._id.toString(), action: e.action, entityType: e.entity_type,
            entityId: e.entity_id, details: e.details_json,
            createdAt: e.createdAt, username: e.admin_id?.username || ""
        }))
    });
}));

// ========== STATIC FILES ==========
app.use("/uploads", express.static(path.join(__dirname, "uploads"), { dotfiles: "deny" }));
app.use("/assets", express.static(path.join(__dirname, "assets"), { dotfiles: "deny" }));

// ========== PAGE SERVING ==========
const protectedPages = new Set([
    "home.html", "mine.html", "invite.html", "account.html", "my-products.html", "bank-setup.html",
    "transactions.html", "spin.html", "recharge.html", "mission.html", "team.html", "withdrawal.html",
    "mock-checkout.html"
]);

function sendPage(req, res, page) {
    const filepath = path.join(__dirname, page);
    if (!fs.existsSync(filepath)) {
        return res.status(404).type("text").send("Page not found.");
    }
    res.sendFile(filepath);
}

function sendLoginPage(req, res) {
    if (req.session.user) return res.redirect(302, "/home.html");
    sendPage(req, res, "index.html");
}

app.get("/", sendLoginPage);
app.get("/index.html", sendLoginPage);
app.get("/about.html", (req, res) => sendPage(req, res, "about.html"));

for (const page of protectedPages) {
    app.get(`/${page}`, asyncRoute(async (req, res) => {
        if (!req.session.user) return res.redirect(302, "/index.html");
        const user = await User.findById(req.session.user.id);
        if (!user || user.status !== "active") {
            req.session.destroy(() => {});
            return res.redirect(302, "/index.html");
        }
        sendPage(req, res, page);
    }));
}

app.get(["/admin", "/admin.html"], (req, res) => {
    res.set("Cache-Control", "no-store");
    sendPage(req, res, "admin.html");
});

// ========== 404 & ERROR HANDLERS ==========
app.use((req, res) => {
    res.status(404).json({ success: false, message: "Not found." });
});

app.use((error, req, res, next) => {
    console.error("Request failed:", error);
    if (res.headersSent) return next(error);
    if (error.type === "entity.too.large") {
        return res.status(413).json({ success: false, message: "Image uploads must be 3 MB or smaller." });
    }
    if (error.type === "entity.parse.failed") {
        return res.status(400).json({ success: false, message: "Request body is invalid." });
    }
    res.status(500).json({ success: false, message: "Server error. Please try again." });
});

// ========== SEED INITIAL DATA ==========
async function seedInitialData() {
    const adminUsername = (process.env.ADMIN_USERNAME || "").trim();
    const adminPassword = process.env.ADMIN_PASSWORD || "";
    if (adminUsername && adminPassword) {
        const adminCount = await Admin.countDocuments();
        if (adminCount === 0) {
            await Admin.create({
                username: adminUsername,
                password_hash: bcrypt.hashSync(adminPassword, 12),
                password_change_required: true
            });
            console.log("Initial admin account created; it must change its password after signing in.");
        }
    }

    const productCount = await Product.countDocuments();
    if (productCount === 0) {
        const initialProducts = [
            { name: "Product A", category: "daily", price_paise: 90000, duration_days: 2, daily_reward_paise: 400000, total_reward_paise: 800000, purchase_limit: 5 },
            { name: "Product B", category: "daily", price_paise: 29500, duration_days: 45, daily_reward_paise: 24000, total_reward_paise: 1080000, purchase_limit: 10 },
            { name: "Product C", category: "daily", price_paise: 55000, duration_days: 10, daily_reward_paise: 140000, total_reward_paise: 1400000, purchase_limit: 10 },
            { name: "Product D", category: "daily", price_paise: 110000, duration_days: 7, daily_reward_paise: 400000, total_reward_paise: 2800000, purchase_limit: 10 },
            { name: "Product F", category: "daily", price_paise: 250000, duration_days: 5, daily_reward_paise: 745000, total_reward_paise: 3725000, purchase_limit: 5 },
            { name: "Product G", category: "daily", price_paise: 499900, duration_days: 2, daily_reward_paise: 2999900, total_reward_paise: 5999800, purchase_limit: 1 },
            { name: "VIP 1", category: "vip", price_paise: 99900, duration_days: 3, daily_reward_paise: 250000, total_reward_paise: 750000, purchase_limit: 10 },
            { name: "VIP 2", category: "vip", price_paise: 150000, duration_days: 2, daily_reward_paise: 600000, total_reward_paise: 1200000, purchase_limit: 10 },
            { name: "VIP 3", category: "vip", price_paise: 300000, duration_days: 2, daily_reward_paise: 1200000, total_reward_paise: 2400000, purchase_limit: 10 },
            { name: "VIP 4", category: "vip", price_paise: 600000, duration_days: 1, daily_reward_paise: 5000000, total_reward_paise: 5000000, purchase_limit: 1 }
        ];
        await Product.insertMany(initialProducts);
    }

    const missionCount = await Mission.countDocuments();
    if (missionCount === 0) {
        const initialMissions = [
            { name: "3 team members", description: "Reach 3 team members", target_members: 3, reward_paise: 5000 },
            { name: "5 team members", description: "Reach 5 team members", target_members: 5, reward_paise: 12000 },
            { name: "10 team members", description: "Reach 10 team members", target_members: 10, reward_paise: 30000 },
            { name: "20 team members", description: "Reach 20 team members", target_members: 20, reward_paise: 70000 },
            { name: "35 team members", description: "Reach 35 team members", target_members: 35, reward_paise: 150000 },
            { name: "50 team members", description: "Reach 50 team members", target_members: 50, reward_paise: 300000 },
            { name: "100 team members", description: "Reach 100 team members", target_members: 100, reward_paise: 700000 }
        ];
        await Mission.insertMany(initialMissions);
    }

    const settingsCount = await SiteSetting.countDocuments();
    if (settingsCount === 0) {
        const initialSettings = [
            { key: "site_name", value: "Finora" },
            { key: "site_logo_url", value: "/assets/images/kingfisher-logo.svg" },
            { key: "site_banner_url", value: "/assets/images/money-hero.svg" },
            { key: "invite_banner_url", value: "" },
            { key: "site_spinner_url", value: "/assets/images/Speener.svg" },
            { key: "support_url", value: "https://t.me/Kingfisher_supportbot" },
            { key: "minimum_recharge_rupees", value: "295" },
            { key: "minimum_withdrawal_rupees", value: "170" },
            { key: "maintenance_mode", value: "false" }
        ];
        await SiteSetting.insertMany(initialSettings);
    }
}

// ========== START SERVER ==========
async function start() {
    await seedInitialData();
    const sessionCleanup = setInterval(async () => {
        try { await SessionModel.deleteMany({ expires: { $lte: new Date() } }); }
        catch (error) { console.error("Session cleanup failed:", error); }
    }, 15 * 60 * 1000);
    sessionCleanup.unref();
    app.listen(port, () => console.log(`Finora server listening on port ${port}`));
}

module.exports = { app, start };
