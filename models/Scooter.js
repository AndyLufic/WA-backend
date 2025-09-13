import mongoose from 'mongoose';

const scooterSchema = new mongoose.Schema(
  {
    model: { type: String, required: true },
    battery: { type: Number, default: 100 },
    status: {
      type: String,
      enum: ['available', 'reserved', 'in_use', 'maintenance', 'offline'],
      default: 'available'
    },
    location: { type: mongoose.Schema.Types.ObjectId, ref: 'Location', required: true },
    lastSeen: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

export default mongoose.model('Scooter', scooterSchema);
