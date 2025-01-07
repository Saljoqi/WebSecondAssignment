import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';


import dotenv from 'dotenv';
dotenv.config()
import jwt from 'jsonwebtoken'; // Import JWT for token generation and verification
import { body, validationResult } from 'express-validator';

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_key';

app.use(express.json());

// MongoDB Connection URI
const uri = process.env.MONGODB_URI;

mongoose
  .connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Connected to MongoDB'))
  .catch((error) => console.error('MongoDB connection error:', error));

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

// Sign-Up Endpoint
app.post(
  '/signup',
  body('username').isLength({ min: 5 }).withMessage('Username should be at least 5 characters long'),
  body('email').isEmail().withMessage('Invalid email address'),
  body('password').isLength({ min: 5 }).withMessage('Password should be at least 5 characters long'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;
    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).send('Email is already in use');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ username, email, password: hashedPassword });
      await user.save();
      res.status(201).send('User registered successfully!');
    } catch (error) {
      res.status(500).send('Error registering user');
    }
  }
);

// Sign-In Endpoint
app.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send('User not found');
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).send('Invalid password');
    }

    const token = jwt.sign({ email: user.email, username: user.username }, JWT_SECRET, {
      expiresIn: '1h', // Token expiration time
    });

    res.status(200).json({ message: 'Sign-In successful!', token });
  } catch (error) {
    res.status(500).send('Error signing in');
  }
});

// Protected Route
app.get('/protected', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Bearer <token>
  if (!token) {
    return res.status(401).json({ message: 'Access token is missing' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.status(200).json({ message: 'Protected route accessed', user: decoded });
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
