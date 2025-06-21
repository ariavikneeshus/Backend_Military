// === Military Asset Management System Server ===
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// ===== DB Connection =====
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// ===== SCHEMAS =====
const baseSchema = new mongoose.Schema({
  name: { type: String, required: true },
  code: { type: String, required: true, unique: true }
});
const Base = mongoose.model('Base', baseSchema);

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'commander', 'logistics'], required: true },
  assignedBase: { type: mongoose.Schema.Types.ObjectId, ref: 'Base' },
  identifier: { type: String, required: true, unique: true },
});
const User = mongoose.model('User', userSchema);

const assetSchema = new mongoose.Schema({
  equipmentType: String,
  base: { type: mongoose.Schema.Types.ObjectId, ref: 'Base' },
  quantity: Number,
  status: { type: String, default: 'active' },
  history: [{
    action: String,
    date: Date,
    quantity: Number,
    fromBase: { type: mongoose.Schema.Types.ObjectId, ref: 'Base' },
    toBase: { type: mongoose.Schema.Types.ObjectId, ref: 'Base' }
  }]
});
const Asset = mongoose.model('Asset', assetSchema);

const purchaseSchema = new mongoose.Schema({
  equipmentType: String,
  quantity: Number,
  base: { type: mongoose.Schema.Types.ObjectId, ref: 'Base' },
  date: { type: Date, default: Date.now },
});
const Purchase = mongoose.model('Purchase', purchaseSchema);

const transferSchema = new mongoose.Schema({
  equipmentType: String,
  quantity: Number,
  fromBase: { type: mongoose.Schema.Types.ObjectId, ref: 'Base' },
  toBase: { type: mongoose.Schema.Types.ObjectId, ref: 'Base' },
  date: { type: Date, default: Date.now },
});
const Transfer = mongoose.model('Transfer', transferSchema);

const assignmentSchema = new mongoose.Schema({
  assignedTo: String,
  equipmentType: String,
  quantity: Number,
  base: { type: mongoose.Schema.Types.ObjectId, ref: 'Base' },
  date: { type: Date, default: Date.now },
});
const Assignment = mongoose.model('Assignment', assignmentSchema);

const expenditureSchema = new mongoose.Schema({
  assignmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Assignment' },
  quantityUsed: Number,
  date: { type: Date, default: Date.now },
});
const Expenditure = mongoose.model('Expenditure', expenditureSchema);

// ===== Middleware =====
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(403).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ===== Auth Routes =====
app.post('/api/register', async (req, res) => {
  const { username, password, role, assignedBase, identifier } = req.body;
  if (!username || !password || !role || !identifier) return res.status(400).json({ error: 'All fields required' });
  if (role !== 'admin' && !assignedBase) return res.status(400).json({ error: 'Assigned base is required for this role' });

  try {
    const exists = await User.findOne({ $or: [{ username }, { identifier }] });
    if (exists) return res.status(400).json({ error: 'Username or Identifier already exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hash, role, assignedBase, identifier });
    await user.save();
    res.status(201).json({ message: 'User registered' });
  } catch {
    res.status(500).json({ error: 'Registration failed' });
  }
});


app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username }).populate('assignedBase');
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({
    id: user._id,
    role: user.role,
    base: user.assignedBase?._id,
    identifier: user.identifier
  }, process.env.JWT_SECRET, { expiresIn: '1d' });

  res.json({ token });
});

// ===== User & Base Routes =====
app.get('/api/user', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).populate('assignedBase');
  res.json(user);
});

app.get('/api/users', authMiddleware, async (req, res) => {
  const { role } = req.query;
  const users = await User.find(role ? { role } : {}).populate('assignedBase');
  res.json(users);
});

app.get('/api/users/:id', authMiddleware, async (req, res) => {
  const user = await User.findById(req.params.id).populate('assignedBase');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

app.post('/api/bases', async (req, res) => {
  const { name, code } = req.body;
  try {
    const base = new Base({ name, code });
    await base.save();
    res.status(201).json(base);
  } catch {
    res.status(500).json({ error: 'Failed to create base' });
  }
});

app.get('/api/bases', async (req, res) => {
  try {
    const bases = await Base.find();
    res.json(bases);
  } catch {
    res.status(500).json({ error: 'Failed to fetch bases' });
  }
});

// ===== Dashboard Route =====
app.get('/api/dashboard', authMiddleware, async (req, res) => {
  try {
    const baseId = req.query.base || req.user.base || req.user.assignedBase;

    const baseFilter = { base: baseId };

    const purchases = await Purchase.find(baseFilter);
    const transferIn = await Transfer.find({ toBase: baseId });
    const transferOut = await Transfer.find({ fromBase: baseId });
    const assignments = await Assignment.find(baseFilter);
    const assignmentIds = assignments.map(a => a._id);
    const expenditures = await Expenditure.find({ assignmentId: { $in: assignmentIds } });

    const totalPurchased = purchases.reduce((a, b) => a + b.quantity, 0);
    const totalIn = transferIn.reduce((a, b) => a + b.quantity, 0);
    const totalOut = transferOut.reduce((a, b) => a + b.quantity, 0);
    const totalAssigned = assignments.reduce((a, b) => a + b.quantity, 0);
    const totalExpended = expenditures.reduce((a, b) => a + b.quantityUsed, 0);
    const netMovement = totalPurchased + totalIn - totalOut;
    const closingBalance = netMovement - totalAssigned - totalExpended;

    res.json({
      openingBalance: 0,
      netMovement,
      closingBalance,
      breakdown: { totalPurchased, totalTransferIn: totalIn, totalTransferOut: totalOut },
      totalAssigned,
      totalExpended
    });
  } catch (err) {
    res.status(500).json({ error: 'Dashboard error' });
  }
});

// ===== Transactions (Purchases, Transfers, Assignments, Expenditures) =====
app.post('/api/purchases', authMiddleware, async (req, res) => {
  const { equipmentType, quantity, base } = req.body;
  const targetBase = req.user.role === 'admin' ? base : req.user.base;
  const purchase = await Purchase.create({ equipmentType, quantity, base: targetBase });
  res.status(201).json(purchase);
});

app.get('/api/purchases', authMiddleware, async (req, res) => {
  const filter = req.user.role === 'admin' ? {} : { base: req.user.base };
  const purchases = await Purchase.find(filter);
  res.json(purchases);
});

app.post('/api/transfers', authMiddleware, async (req, res) => {
  const { equipmentType, quantity, fromBase, toBase } = req.body;
  const source = req.user.role === 'admin' ? fromBase : req.user.base;
  const transfer = await Transfer.create({ equipmentType, quantity, fromBase: source, toBase });
  res.status(201).json(transfer);
});

app.get('/api/transfers', authMiddleware, async (req, res) => {
  const filter = req.user.role === 'admin'
    ? {}
    : { $or: [{ fromBase: req.user.base }, { toBase: req.user.base }] };
  const transfers = await Transfer.find(filter).populate('fromBase toBase');
  res.json(transfers);
});

app.post('/api/assignments', authMiddleware, async (req, res) => {
  const { assignedTo, equipmentType, quantity, base } = req.body;
  const baseId = req.user.role === 'admin' ? base : req.user.base;
  const assignment = await Assignment.create({ assignedTo, equipmentType, quantity, base: baseId });
  res.status(201).json(assignment);
});

app.get('/api/assignments', authMiddleware, async (req, res) => {
  const filter = req.user.role === 'admin' ? {} : { base: req.user.base };
  const assignments = await Assignment.find(filter);
  res.json(assignments);
});

app.post('/api/expenditures', authMiddleware, async (req, res) => {
  const { assignmentId, quantityUsed } = req.body;
  const expenditure = await Expenditure.create({ assignmentId, quantityUsed });
  res.status(201).json(expenditure);
});

app.get('/api/expenditures', authMiddleware, async (req, res) => {
  const expenditures = await Expenditure.find().populate('assignmentId');
  res.json(expenditures);
});

// ===== Server Start =====
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
