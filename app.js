require('dotenv').config();
import express, { json } from 'express';
import { connect, Schema, model } from 'mongoose';
import { verify, sign } from 'jsonwebtoken';
import { hash, compare } from 'bcryptjs';
const app = express();

app.use(json());
app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.url}`);
  next();
});

// Kết nối MongoDB
connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Định nghĩa schema
const userSchema = new Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const todoSchema = new Schema({
  task: { type: String, required: true },
  completed: { type: Boolean, default: false },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
});
const User = model('User', userSchema);
const Todo = model('Todo', todoSchema);

// Middleware xác thực JWT
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// POST /register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    const hashedPassword = await hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered' });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  try {
    const user = await User.findOne({ username });
    if (!user || !(await compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// GET /todos
app.get('/todos', authMiddleware, async (req, res) => {
  try {
    const { completed } = req.query;
    const filter = { userId: req.userId };
    if (completed) filter.completed = completed === 'true';
    const todos = await Todo.find(filter);
    res.status(200).json(todos);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /todos
app.post('/todos', authMiddleware, async (req, res) => {
  const { task, completed } = req.body;
  if (!task || typeof task !== 'string') {
    return res.status(400).json({ error: 'Invalid input: task is required' });
  }
  try {
    const todo = new Todo({ task, completed: completed ?? false, userId: req.userId });
    await todo.save();
    res.status(201).json(todo);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// PUT /todos/:id
app.put('/todos/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { task, completed } = req.body;
  if (!task || typeof task !== 'string') {
    return res.status(400).json({ error: 'Invalid input: task is required' });
  }
  try {
    const todo = await Todo.findOneAndUpdate(
      { _id: id, userId: req.userId },
      { task, completed: completed ?? false },
      { new: true }
    );
    if (!todo) {
      return res.status(404).json({ error: 'Todo not found' });
    }
    res.status(200).json(todo);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// DELETE /todos/:id
app.delete('/todos/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const todo = await Todo.findOneAndDelete({ _id: id, userId: req.userId });
    if (!todo) {
      return res.status(404).json({ error: 'Todo not found' });
    }
    res.status(200).json({ message: 'Todo deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Handle invalid routes
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(process.env.PORT || 3000, '0.0.0.0', () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});