import 'dotenv/config';
import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors());               // allow frontend (Vite) on localhost
app.use(express.json());       // parse JSON bodies

// ---- In-memory data store (replace with DB later) ----
let scooters = [
  { id: 's_1', lat: 44.868, lng: 13.848, model: 'Xiaomi M365', city: 'Pula', battery: 92, status: 'available', lastSeen: new Date().toISOString() }
];
const VALID_STATUSES = new Set(['available','reserved','in_use','maintenance','offline']);
const makeId = () => 's_' + Math.random().toString(36).slice(2, 9);

// ----------- Routes (CRUD) -----------
app.get('/api/scooters', (req, res) => {
  const { city, status } = req.query;
  let data = scooters;
  if (city) data = data.filter(s => s.city.toLowerCase() === String(city).toLowerCase());
  if (status) data = data.filter(s => s.status === status);
  res.json(data);
});

app.get('/api/scooters/:id', (req, res) => {
  const s = scooters.find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  res.json(s);
});

app.post('/api/scooters', (req, res) => {
  const { lat, lng, model, city, battery = 100, status = 'available' } = req.body || {};
  if (typeof lat !== 'number' || typeof lng !== 'number' || !model || !city || !VALID_STATUSES.has(status)) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  const scooter = { id: makeId(), lat, lng, model, city, battery: Number(battery), status, lastSeen: new Date().toISOString() };
  scooters.push(scooter);
  res.status(201).json(scooter);
});

app.patch('/api/scooters/:id', (req, res) => {
  const s = scooters.find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  const { lat, lng, model, city, battery, status } = req.body || {};
  if (status && !VALID_STATUSES.has(status)) return res.status(400).json({ error: 'Invalid status' });
  if (lat !== undefined) s.lat = Number(lat);
  if (lng !== undefined) s.lng = Number(lng);
  if (model !== undefined) s.model = model;
  if (city !== undefined) s.city = city;
  if (battery !== undefined) s.battery = Number(battery);
  s.lastSeen = new Date().toISOString();
  if (status !== undefined) s.status = status;
  res.json(s);
});

app.delete('/api/scooters/:id', (req, res) => {
  const i = scooters.findIndex(x => x.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: 'Not found' });
  scooters.splice(i, 1);
  res.status(204).send();
});

// ----------- Start server -----------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`API running at http://localhost:${PORT}`));
