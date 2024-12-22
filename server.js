const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const cors = require('cors');

// Разрешить запросы с вашего домена
const corsOptions = {
  origin: 'https://vtjvlad.github.io/TrexYield/', // Ваш домен GitHub Pages
  methods: ['GET', 'POST'], // Методи, які ви дозволяєте
  allowedHeaders: ['Content-Type', 'Authorization'] 
};



const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
app.use(cors(corsOptions));
app.use(express.static('public'));

// Главная страница
app.get('/', (req, res) => {
  console.log('GET / - Главная страница загружается');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});



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

// Middleware
app.use(express.json());

// Регистрация
app.post('/register', async (req, res) => {
  try {
    console.log('POST /register - Получен запрос на регистрацию');
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      console.log('POST /register - Некорректные данные');
      return res.status(400).json({ message: 'Username, email, and password are required' });
    }

    console.log(`POST /register - Данные пользователя: ${username}, ${email}`);
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    console.log(`POST /register - Пользователь ${username} успешно зарегистрирован`);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    if (error.code === 11000) {
      console.log('POST /register - Пользователь или email уже существует');
      return res.status(400).json({ message: 'Username or email already exists' });
    }
    console.error('POST /register - Ошибка сервера:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Модель пользователя tg
const tgUserSchema = new mongoose.Schema({
  telegramId: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  First_name: { type: String, required: true },
	Last_name: { type: String, required: false },
}, { collection: 'tg users' }
);

const tgUser = mongoose.model('tgUser', tgUserSchema);



// Регистрация
app.post('/register/tg', async (req, res) => {
  try {
    console.log('POST /register - Получен запрос на регистрацию');
    const { telegramId, username, First_name, Last_name } = req.body;

    if (!telegramId || !username || !First_name) {
      console.log('POST /tg/register - Некорректные данные');
      return res.status(400).json({ message: 'invotect userData' });
    }

    console.log(`POST /tg/register - Данные пользователя: ${username}, ${telegramId}`);
    

    const tg_user = new tgUser({ telegramId, username, First_name, Last_name, });
    await tg_user.save();

    console.log(`POST /tg/register - Пользователь ${username} успешно зарегистрирован`);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    if (error.code === 11000) {
      console.log('POST /tg/register - Пользователь  уже существует');
      return res.status(400).json({ message: 'Username  already exists' });
    }
    console.error('POST /tg/register - Ошибка сервера:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// Авторизация
app.post('/login', async (req, res) => {
  try {
    console.log('POST /login - Получен запрос на авторизацию');
    const { login, password } = req.body;

    console.log(`POST /login - Попытка входа с логином: ${login}`);
    const user = await User.findOne({ $or: [{ username: login }, { email: login }] });

    if (!user) {
      console.log('POST /login - Неверные учетные данные');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('POST /login - Неверный пароль');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET);
    console.log(`POST /login - Пользователь ${user.username} успешно авторизован`);

    res.json({ token });
  } catch (error) {
    console.error('POST /login - Ошибка сервера:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Защищенный маршрут (пример)
app.get('/protected', authenticateToken, (req, res) => {
  console.log('GET /protected - Пользователь получил доступ к защищенному маршруту');
  res.json({
    message: 'Protected route accessed successfully',
    userId: req.user.userId,
    username: req.user.username
  });
});

// Middleware для проверки JWT
function authenticateToken(req, res, next) {
  console.log('Middleware - Проверка JWT');
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('Middleware - Токен отсутствует');
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Middleware - Неверный токен');
      return res.sendStatus(403);
    }
    console.log(`Middleware - Токен проверен, пользователь: ${user.username}`);
    req.user = user;
    next();
  });
}

app.listen(PORT, '0.0.0.0', () => { 
  console.log(`Server running on port ${PORT}`);
});