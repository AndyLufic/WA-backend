import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';            // <-- use bcryptjs
import jwt from 'jsonwebtoken';

import User from './models/User.js';
import Location from './models/Location.js';
import Scooter from './models/Scooter.js';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const MONGO_URI = process.env.MONGO_URI;

// ----------------- DB -----------------
await mongoose
  .connect(MONGO_URI, { dbName: 'scooterapp' })
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => {
    console.error('MongoDB error:', err);
    process.exit(1);
  });

// ---- Seed demo users (provider & customer) if none exist ----
if ((await User.countDocuments()) === 0) {
  const [provHash, custHash] = await Promise.all([
    bcrypt.hash('provider123', 10),
    bcrypt.hash('customer123', 10),
  ]);
  await User.create([
    { email: 'provider@demo.com', passwordHash: provHash, role: 'provider' },
    { email: 'customer@demo.com', passwordHash: custHash, role: 'customer' },
  ]);
  console.log('👤 Seeded users: provider@demo.com / provider123 & customer@demo.com / customer123');
}

// ---- Seed demo LOCATIONS + SCOOTERS if DB is empty ----
async function seedIfEmpty() {
  const locCount = await Location.countDocuments();
  if (locCount > 0) return;

  const locations = await Location.create([
    { name: 'Pula Center',  city: 'Pula', lat: 44.8666, lng: 13.8496 },
    { name: 'Pula Harbor',  city: 'Pula', lat: 44.8700, lng: 13.8530 },
    { name: 'Veruda Park',  city: 'Pula', lat: 44.8522, lng: 13.8445 },
  ]);

  const [center, harbor, veruda] = locations;

  await Scooter.create([
    { model: 'Xiaomi M365', battery: 92, status: 'available',   location: center._id },
    { model: 'Ninebot ES2', battery: 75, status: 'maintenance', location: center._id },
    { model: 'Bird Flex',   battery: 88, status: 'available',   location: harbor._id },
    { model: 'Lime Gen4',   battery: 63, status: 'reserved',    location: veruda._id },
  ]);

  console.log('🌱 Seeded demo locations & scooters');
}
await seedIfEmpty();

// ----------------- Auth helpers -----------------
function signToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// If a route needs a logged-in user, call auth().
// If it needs a specific role, call auth('provider').
function auth(requiredRole = null) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (requiredRole && decoded.role !== requiredRole) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      req.user = decoded;
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// ----------------- AUTH -----------------
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, role } = req.body || {};
    if (!email || !password || !['customer', 'provider'].includes(role)) {
      return res.status(400).json({ error: 'email, password, role required' });
    }
    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: 'Email already in use' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash, role });
    const token = signToken(user);
    res.status(201).json({ token, user: { id: user._id, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken(user);
    res.json({ token, user: { id: user._id, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', auth(), async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ id: user._id, email: user.email, role: user.role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ----------------- LOCATIONS -----------------
app.get('/api/locations', async (_req, res) => {
  try {
    const locations = await Location.find().lean();
    res.json(locations);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/locations/:id', async (req, res) => {
  try {
    const location = await Location.findById(req.params.id).lean();
    if (!location) return res.status(404).json({ error: 'Location not found' });
    const scooters = await Scooter.find({ location: location._id }).lean();
    res.json({ ...location, scooters });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/locations', auth('provider'), async (req, res) => {
  try {
    const { name, city, lat, lng } = req.body || {};
    if (!name || !city || typeof lat !== 'number' || typeof lng !== 'number') {
      return res.status(400).json({ error: 'name, city, lat, lng required' });
    }
    const loc = await Location.create({ name, city, lat, lng });
    res.status(201).json(loc);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.patch('/api/locations/:id', auth('provider'), async (req, res) => {
  try {
    const loc = await Location.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!loc) return res.status(404).json({ error: 'Not found' });
    res.json(loc);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/locations/:id', auth('provider'), async (req, res) => {
  try {
    await Scooter.deleteMany({ location: req.params.id }); // cascade delete scooters
    const result = await Location.findByIdAndDelete(req.params.id);
    if (!result) return res.status(404).json({ error: 'Not found' });
    res.status(204).send();
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ----------------- SCOOTERS -----------------
// Filterable: /api/scooters?location=<id>&status=<status>
app.get('/api/scooters', async (req, res) => {
  try {
    const where = {};
    if (req.query.location) where.location = req.query.location;
    if (req.query.status) where.status = req.query.status;

    const scooters = await Scooter.find(where).populate('location').lean();
    res.json(scooters);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/scooters/:id', async (req, res) => {
  try {
    const s = await Scooter.findById(req.params.id).populate('location').lean();
    if (!s) return res.status(404).json({ error: 'Not found' });
    res.json(s);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/scooters', auth('provider'), async (req, res) => {
  try {
    const { model, battery = 100, status = 'available', location } = req.body || {};
    if (!location) return res.status(400).json({ error: 'Location is required' });
    const exists = await Location.findById(location);
    if (!exists) return res.status(400).json({ error: 'Invalid location' });

    const scooter = await Scooter.create({ model, battery, status, location });
    res.status(201).json(scooter);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.patch('/api/scooters/:id', auth('provider'), async (req, res) => {
  try {
    const s = await Scooter.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!s) return res.status(404).json({ error: 'Not found' });
    res.json(s);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/scooters/:id', auth('provider'), async (req, res) => {
  try {
    const s = await Scooter.findByIdAndDelete(req.params.id);
    if (!s) return res.status(404).json({ error: 'Not found' });
    res.status(204).send();
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ----------------- Start -----------------
app.listen(PORT, () => console.log(`🚀 API running at http://localhost:${PORT}`));
