import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

/* ==========================
   0) Config & App
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
   1) Schemas & Models
   ========================== */

const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['customer', 'provider'], required: true },
    alias: { type: String, trim: true, default: '' },
  },
  { timestamps: true }
);

const locationSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    city: { type: String, required: true, trim: true },
    lat: { type: Number, required: true },
    lng: { type: Number, required: true },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, // ownership
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
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, // ownership
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);
const Location = mongoose.model('Location', locationSchema);
const Scooter = mongoose.model('Scooter', scooterSchema);

/* ==========================
   2) Auth helpers & middleware
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
  if (req.user?.role !== 'provider') return res.status(403).json({ error: 'Provider role required' });
  next();
}

/* ==========================
   3) Auth routes (signup, login, me)
   ========================== */

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, role, alias = '' } = req.body || {};
    if (!email || !password || !role) return res.status(400).json({ error: 'Missing fields' });
    if (!['customer', 'provider'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Email already in use' });

    const passwordHash = bcrypt.hashSync(String(password), 10);
    const u = await User.create({ email, passwordHash, role, alias });

    const token = sign(u);
    res.status(201).json({ token, user: { id: u._id, email: u.email, role: u.role, alias: u.alias } });
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

    const ok = bcrypt.compareSync(String(password), u.passwordHash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

    const token = sign(u);
    res.json({ token, user: { id: u._id, email: u.email, role: u.role, alias: u.alias } });
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
   4) Profile routes (alias & password)
   ========================== */

// PUT /api/users/me  (update alias)
app.put('/api/users/me', authRequired, async (req, res) => {
  const { alias = '' } = req.body || {};
  const u = await User.findByIdAndUpdate(
    req.user.id,
    { alias: String(alias).trim().slice(0, 40) },
    { new: true, select: '_id email role alias' }
  );
  res.json({ id: u._id, email: u.email, role: u.role, alias: u.alias });
});

// PUT /api/users/me/password  (change password)
app.put('/api/users/me/password', authRequired, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });

  const u = await User.findById(req.user.id);
  if (!u) return res.status(404).json({ error: 'Not found' });

  const ok = bcrypt.compareSync(String(currentPassword), u.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Current password incorrect' });

  u.passwordHash = bcrypt.hashSync(String(newPassword), 10);
  await u.save();
  res.json({ success: true });
});

/* ==========================
   5) Locations 
   ========================== */

// GET public
app.get('/api/locations', async (_req, res) => {
  const items = await Location.find().sort({ createdAt: -1 }).select('-owner'); 
  res.json(items);
});

// GET  provider-owned list
app.get('/api/locations/mine', authRequired, providerOnly, async (req, res) => {
  const items = await Location.find({ owner: req.user.id }).sort({ createdAt: -1 });
  res.json(items);
});

// POST  provider creates; sets owned
app.post('/api/locations', authRequired, providerOnly, async (req, res) => {
  const { name, city, lat, lng } = req.body || {};
  if (!name || !city || typeof lat !== 'number' || typeof lng !== 'number') {
    return res.status(400).json({ error: 'Invalid input' });
  }
  const loc = await Location.create({ name, city, lat, lng, owner: req.user.id });
  res.status(201).json(loc);
});

// PATCH provider may update ONLY own
app.patch('/api/locations/:id', authRequired, providerOnly, async (req, res) => {
  const { name, city, lat, lng } = req.body || {};
  const patch = {};
  if (name !== undefined) patch.name = name;
  if (city !== undefined) patch.city = city;
  if (lat !== undefined) patch.lat = Number(lat);
  if (lng !== undefined) patch.lng = Number(lng);

  // ensure ownership
  const loc = await Location.findOneAndUpdate(
    { _id: req.params.id, owner: req.user.id },
    patch,
    { new: true }
  );
  if (!loc) return res.status(404).json({ error: 'Not found' });
  res.json(loc);
});

// DELETE provider may delete ONLY own; cascade scooters
app.delete('/api/locations/:id', authRequired, providerOnly, async (req, res) => {
  const loc = await Location.findOneAndDelete({ _id: req.params.id, owner: req.user.id });
  if (!loc) return res.status(404).json({ error: 'Not found' });

  // delete only scooters owned by the same provider at that location
  await Scooter.deleteMany({ location: loc._id, owner: req.user.id });
  res.status(204).send();
});

/* ==========================
   6) Scooters (public read; provider write with ownership)
   ========================== */

// GET /api/scooters 
app.get('/api/scooters', async (req, res) => {
  const { location } = req.query;
  const q = location ? { location } : {};
  const items = await Scooter.find(q)
    .populate({ path: 'location', select: 'name city lat lng' })
    .sort({ createdAt: -1 })
    .select('-owner'); // hide owner in public read
  res.json(items);
});

// provider-owned list
app.get('/api/scooters/mine', authRequired, providerOnly, async (req, res) => {
  const { location } = req.query;
  const q = { owner: req.user.id };
  if (location) q.location = location;
  const items = await Scooter.find(q)
    .populate({ path: 'location', select: 'name city lat lng' })
    .sort({ createdAt: -1 });
  res.json(items);
});

// provider creates; must reference provider's location
app.post('/api/scooters', authRequired, providerOnly, async (req, res) => {
  const { model, battery = 100, status = 'available', location } = req.body || {};
  if (!model || !location) return res.status(400).json({ error: 'Missing fields' });

  // Ensure the location belongs to this provider
  const loc = await Location.findOne({ _id: location, owner: req.user.id });
  if (!loc) return res.status(400).json({ error: 'Invalid location' });

  const sc = await Scooter.create({
    model,
    battery: Number(battery),
    status,
    location: loc._id,
    owner: req.user.id,
  });
  const populated = await sc.populate({ path: 'location', select: 'name city lat lng' });
  res.status(201).json(populated);
});

// provider may update ONLY own
app.patch('/api/scooters/:id', authRequired, providerOnly, async (req, res) => {
  const { model, battery, status, location } = req.body || {};

  // ensure the scooter is owned by this provider
  const sc = await Scooter.findOne({ _id: req.params.id, owner: req.user.id });
  if (!sc) return res.status(404).json({ error: 'Not found' });

  if (model !== undefined) sc.model = model;
  if (battery !== undefined) sc.battery = Number(battery);
  if (status !== undefined) sc.status = status;

  if (location !== undefined) {
    // new location must also belong to this provider
    const loc = await Location.findOne({ _id: location, owner: req.user.id });
    if (!loc) return res.status(400).json({ error: 'Invalid location' });
    sc.location = loc._id;
  }

  await sc.save();
  const populated = await sc.populate({ path: 'location', select: 'name city lat lng' });
  res.json(populated);
});

// provider may delete ONLY own
app.delete('/api/scooters/:id', authRequired, providerOnly, async (req, res) => {
  const sc = await Scooter.findOneAndDelete({ _id: req.params.id, owner: req.user.id });
  if (!sc) return res.status(404).json({ error: 'Not found' });
  res.status(204).send();
});

/*  7) Dev-only password reset  */
if (process.env.DEV_RESET_SECRET) {
  app.post('/api/dev/force-reset-password', async (req, res) => {
    try {
      const { secret, email, newPassword } = req.body || {};
      if (secret !== process.env.DEV_RESET_SECRET) return res.status(403).json({ error: 'Forbidden' });
      if (!email || !newPassword) return res.status(400).json({ error: 'Missing fields' });

      const u = await User.findOne({ email: String(email).toLowerCase() });
      if (!u) return res.status(404).json({ error: 'User not found' });

      u.passwordHash = bcrypt.hashSync(String(newPassword), 10);
      await u.save();
      res.json({ ok: true });
    } catch (err) {
      console.error('force-reset-password failed:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });
}

//start
app.listen(PORT, () => console.log(`🚀 API running at https://wa-backend-gw0k.onrender.com:${PORT}`));
