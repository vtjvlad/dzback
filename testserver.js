const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Для HMAC проверки
require('dotenv').config();
const cors = require('cors');
const path = require('path');

// Разрешить запросы с вашего домена
const corsOptions = {
  origin: 'https://vtjvlad.github.io/TrexYield/', // Ваш домен GitHub Pages
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const BOT_TOKEN = process.env.BOT_TOKEN; // Токен вашего бота

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static('public'));

// Подключение к MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Модель пользователя
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', UserSchema);

// Модель пользователя Telegram
const tgUserSchema = new mongoose.Schema({
  telegramId: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  First_name: { type: String, required: true },
  Last_name: { type: String, required: false },
}, { collection: 'tg users' });

const tgUser = mongoose.model('tgUser', tgUserSchema);

// Главная страница
app.get('/', (req, res) => {
  console.log('GET / - Главная страница загружается');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Регистрация пользователя
app.post('/register', async (req, res) => {
  try {
console.log('POST /register -  Income request to register!')
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Username, email, and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Регистрация через Telegram
app.post('/register/tg', async (req, res) => {
  try {
    const { telegramId, username, First_name, Last_name } = req.body;

    if (!telegramId || !username || !First_name) {
      return res.status(400).json({ message: 'Invalid userData' });
    }

    const tg_user = new tgUser({ telegramId, username, First_name, Last_name });
    await tg_user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ message: 'Username already exists' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Авторизация пользователя
app.post('/login', async (req, res) => {
  try {
    const { login, password } = req.body;
    const user = await User.findOne({ $or: [{ username: login }, { email: login }] });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET);
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Авторизация через Telegram WebApp
app.post('/auth/telegram', async (req, res) => {
  try {
    const { initData } = req.body;

    if (!initData) {
      return res.status(400).json({ message: 'No data provided' });
    }

    // Проверка подписи
    const isValid = validateTelegramData(initData, BOT_TOKEN);
    if (!isValid) {
      return res.status(403).json({ message: 'Invalid Telegram data' });
    }

    const userData = parseInitData(initData);
    const { id: telegramId, username, first_name: First_name, last_name: Last_name } = userData;

    let user = await tgUser.findOne({ telegramId });
    if (!user) {
      user = new tgUser({ telegramId, username, First_name, Last_name });
      await user.save();
    }

    const token = jwt.sign({ userId: user._id, telegramId: user.telegramId, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Middleware для проверки JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Функция для проверки подписи данных Telegram
function validateTelegramData(initData, botToken) {
  const secretKey = crypto.createHash('sha256').update(botToken).digest();
  const params = new URLSearchParams(initData);

  const hash = params.get('hash');
  params.delete('hash');

  const dataCheckString = [...params.entries()]
    .map(([key, value]) => `${key}=${value}`)
    .sort()
    .join('\n');

  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  return hmac === hash;
}

// Функция для парсинга initData
function parseInitData(initData) {
  const params = new URLSearchParams(initData);
  return JSON.parse(decodeURIComponent(params.get('user')));
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
