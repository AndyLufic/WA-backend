import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

/* ==========================
   1) Setup & DB connection
   ========================== */
const app = express();
app.use(cors());
app.use(express.json());

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/scooter_rental';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const PORT = process.env.PORT || 4000;

mongoose.set('strictQuery', true);
mongoose
  .connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => {
    console.error('❌ MongoDB connection error', err);
    process.exit(1);
  });

/* ==========================
   2) Schemas & Models
   ========================== */
const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['customer', 'provider'], required: true },
    alias: { type: String, trim: true, default: '' }, // << NEW
  },
  { timestamps: true }
);

const locationSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    city: { type: String, required: true, trim: true },
    lat: { type: Number, required: true },
    lng: { type: Number, required: true },
  },
  { timestamps: true }
);

const scooterSchema = new mongoose.Schema(
  {
    model: { type: String, required: true, trim: true },
    battery: { type: Number, default: 100, min: 0, max: 100 },
    status: {
      type: String,
      enum: ['available', 'reserved', 'in_use', 'maintenance', 'offline'],
      default: 'available',
    },
    location: { type: mongoose.Schema.Types.ObjectId, ref: 'Location', required: true },
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);
const Location = mongoose.model('Location', locationSchema);
const Scooter = mongoose.model('Scooter', scooterSchema);

/* ==========================
   3) Auth helpers & middleware
   ========================== */
function sign(user) {
  return jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function providerOnly(req, res, next) {
  if (req.user?.role !== 'provider') {
    return res.status(403).json({ error: 'Provider role required' });
  }
  next();
}

/* ==========================
   4) Auth routes (signup, login, me)
   ========================== */

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, role, alias = '' } = req.body || {};
    if (!email || !password || !role) return res.status(400).json({ error: 'Missing fields' });
    if (!['customer', 'provider'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Email already in use' });

    const passwordHash = await bcrypt.hash(String(password), 10);
    const u = await User.create({ email, passwordHash, role, alias });

    const token = sign(u);
    res.status(201).json({
      token,
      user: { id: u._id, email: u.email, role: u.role, alias: u.alias },
    });
  } catch (e) {
    res.status(400).json({ error: e.message || 'Signup failed' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    const u = await User.findOne({ email: email.toLowerCase() });
    if (!u) return res.status(400).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(String(password), u.passwordHash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

    const token = sign(u);
    res.json({
      token,
      user: { id: u._id, email: u.email, role: u.role, alias: u.alias },
    });
  } catch (e) {
    res.status(400).json({ error: e.message || 'Login failed' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authRequired, async (req, res) => {
  const u = await User.findById(req.user.id).select('_id email role alias');
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({ id: u._id, email: u.email, role: u.role, alias: u.alias });
});

/* ==========================
   5) Profile routes (alias, password)
   ========================== */

// PUT /api/users/me  (update alias)
app.put('/api/users/me', authRequired, async (req, res) => {
  const { alias = '' } = req.body || {};
  const u = await User.findByIdAndUpdate(
    req.user.id,
    { alias: String(alias).trim().slice(0, 40) },
    { new: true }
  ).select('_id email role alias');
  res.json({ id: u._id, email: u.email, role: u.role, alias: u.alias });
});

// PUT /api/users/me/password  (change password)
app.put('/api/users/me/password', authRequired, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  const u = await User.findById(req.user.id);
  if (!u) return res.status(404).json({ error: 'Not found' });

  const ok = await bcrypt.compare(String(currentPassword), u.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Current password incorrect' });

  u.passwordHash = await bcrypt.hash(String(newPassword), 10);
  await u.save();
  res.json({ success: true });
});

/* ==========================
   6) Locations (provider-only for write)
   ========================== */

// GET /api/locations
app.get('/api/locations', async (req, res) => {
  const items = await Location.find().sort({ createdAt: -1 });
  res.json(items);
});

// POST /api/locations
app.post('/api/locations', authRequired, providerOnly, async (req, res) => {
  const { name, city, lat, lng } = req.body || {};
  if (!name || !city || typeof lat !== 'number' || typeof lng !== 'number') {
    return res.status(400).json({ error: 'Invalid input' });
  }
  const loc = await Location.create({ name, city, lat, lng });
  res.status(201).json(loc);
});

// PATCH /api/locations/:id
app.patch('/api/locations/:id', authRequired, providerOnly, async (req, res) => {
  const { name, city, lat, lng } = req.body || {};
  const patch = {};
  if (name !== undefined) patch.name = name;
  if (city !== undefined) patch.city = city;
  if (lat !== undefined) patch.lat = Number(lat);
  if (lng !== undefined) patch.lng = Number(lng);

  const loc = await Location.findByIdAndUpdate(req.params.id, patch, { new: true });
  if (!loc) return res.status(404).json({ error: 'Not found' });
  res.json(loc);
});

// DELETE /api/locations/:id  (cascade delete scooters)
app.delete('/api/locations/:id', authRequired, providerOnly, async (req, res) => {
  const loc = await Location.findByIdAndDelete(req.params.id);
  if (!loc) return res.status(404).json({ error: 'Not found' });
  await Scooter.deleteMany({ location: loc._id });
  res.status(204).send();
});

/* ==========================
   7) Scooters (public read, provider write)
   ========================== */

// GET /api/scooters  (optional ?location=<id>)
app.get('/api/scooters', async (req, res) => {
  const { location } = req.query;
  const q = location ? { location } : {};
  const items = await Scooter.find(q).populate('location').sort({ createdAt: -1 });
  res.json(items);
});

// POST /api/scooters
app.post('/api/scooters', authRequired, providerOnly, async (req, res) => {
  const { model, battery = 100, status = 'available', location } = req.body || {};
  if (!model || !location) return res.status(400).json({ error: 'Missing fields' });
  const locExists = await Location.findById(location);
  if (!locExists) return res.status(400).json({ error: 'Invalid location' });

  const sc = await Scooter.create({
    model,
    battery: Number(battery),
    status,
    location,
  });
  const populated = await sc.populate('location');
  res.status(201).json(populated);
});

// PATCH /api/scooters/:id
app.patch('/api/scooters/:id', authRequired, providerOnly, async (req, res) => {
  const { model, battery, status, location } = req.body || {};
  const patch = {};
  if (model !== undefined) patch.model = model;
  if (battery !== undefined) patch.battery = Number(battery);
  if (status !== undefined) patch.status = status;
  if (location !== undefined) {
    const locExists = await Location.findById(location);
    if (!locExists) return res.status(400).json({ error: 'Invalid location' });
    patch.location = location;
  }
  const sc = await Scooter.findByIdAndUpdate(req.params.id, patch, { new: true }).populate('location');
  if (!sc) return res.status(404).json({ error: 'Not found' });
  res.json(sc);
});

// DELETE /api/scooters/:id
app.delete('/api/scooters/:id', authRequired, providerOnly, async (req, res) => {
  const sc = await Scooter.findByIdAndDelete(req.params.id);
  if (!sc) return res.status(404).json({ error: 'Not found' });
  res.status(204).send();
});

/* ==========================
   8) Start server
   ========================== */
app.listen(PORT, () => console.log(`🚀 API running at http://localhost:${PORT}`));
