/**
 * VulnShop - Intentionally Vulnerable Shopping Demo
 *
 * Vulnerable libraries used:
 *  - lodash@4.17.4        → CVE-2019-10744  (prototype pollution)
 *  - axios@0.18.0         → CVE-2019-10742  (DoS via large response)
 *  - serialize-javascript@1.7.0 → CVE-2019-16769 (XSS)
 *  - node-fetch@2.6.0     → CVE-2022-0235   (SSRF)
 *  - minimist@1.2.0       → CVE-2020-7598   (prototype pollution)
 *  - express@4.16.0       → CVE-2022-24999  (open redirect)
 *  - ejs@3.1.6            → CVE-2022-29078  (RCE via template injection)
 *  - jsonwebtoken@8.3.0   → CVE-2022-23529  (remote code execution)
 */

const express    = require('express');
const bodyParser = require('body-parser');
const lodash     = require('lodash');
const serialize  = require('serialize-javascript');
const jwt        = require('jsonwebtoken');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ─────────────────────────────────────────────────────────────────
// NOTE: express.static is placed AFTER all routes so API routes take priority.
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ── In-Memory Data Store ───────────────────────────────────────────────────────
const products = [
  { id: 1, name: 'Laptop Pro',      price: 1299.99, category: 'Electronics', stock: 15,  image: '💻' },
  { id: 2, name: 'Wireless Mouse',  price: 29.99,   category: 'Electronics', stock: 50,  image: '🖱️'  },
  { id: 3, name: 'Coffee Mug',      price: 12.99,   category: 'Kitchen',     stock: 100, image: '☕' },
  { id: 4, name: 'Running Shoes',   price: 89.99,   category: 'Sports',      stock: 30,  image: '👟' },
  { id: 5, name: 'JavaScript Book', price: 49.99,   category: 'Books',       stock: 25,  image: '📚' },
  { id: 6, name: 'USB-C Hub',       price: 39.99,   category: 'Electronics', stock: 40,  image: '🔌' },
];

const users  = [];
const orders = [];
const SECRET = 'super-secret-key-dont-use-in-prod';

// ── API Routes ─────────────────────────────────────────────────────────────────

// Home – product listing (JSON API)
app.get('/', (req, res) => {
  const { search, category } = req.query;

  // Uses lodash@4.17.4 – vulnerable to prototype pollution (CVE-2019-10744)
  let filtered = lodash.cloneDeep(products);

  if (search) {
    filtered = lodash.filter(filtered, p =>
      lodash.includes(p.name.toLowerCase(), search.toLowerCase())
    );
  }
  if (category) {
    filtered = lodash.filter(filtered, { category });
  }

  const categories = lodash.uniq(lodash.map(products, 'category'));

  res.json({ products: filtered, categories, total: filtered.length });
});

// Product detail
app.get('/products/:id', (req, res) => {
  const product = lodash.find(products, { id: parseInt(req.params.id) });
  if (!product) return res.status(404).json({ error: 'Product not found' });

  // serialize-javascript@1.7.0 – CVE-2019-16769 (XSS via unescaped chars)
  const serialized = serialize(product, { isJSON: true });
  res.json({ product, serialized });
});

// User registration
app.post('/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields required' });

  if (lodash.find(users, { email }))
    return res.status(409).json({ error: 'Email already registered' });

  const user = { id: users.length + 1, username, email, password, createdAt: new Date() };
  users.push(user);

  // jsonwebtoken@8.3.0 – CVE-2022-23529
  const token = jwt.sign({ userId: user.id, email }, SECRET, { expiresIn: '24h' });
  res.status(201).json({ message: 'Registered successfully', token, userId: user.id });
});

// User login
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = lodash.find(users, { email, password });

  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id, email }, SECRET, { expiresIn: '24h' });
  res.json({ token, user: lodash.omit(user, ['password']) });
});

// JWT middleware
const authenticate = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(auth.replace('Bearer ', ''), SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Cart & checkout
app.post('/orders', authenticate, (req, res) => {
  const { items } = req.body;
  if (!items?.length) return res.status(400).json({ error: 'Cart is empty' });

  const orderItems = items.map(({ productId, quantity }) => {
    const product = lodash.find(products, { id: productId });
    if (!product) throw new Error(`Product ${productId} not found`);
    return { ...product, quantity, subtotal: product.price * quantity };
  });

  const total = lodash.sumBy(orderItems, 'subtotal');
  const order = {
    id: orders.length + 1,
    userId: req.user.userId,
    items: orderItems,
    total: lodash.round(total, 2),
    status: 'confirmed',
    createdAt: new Date(),
  };
  orders.push(order);
  res.status(201).json({ order, message: 'Order placed successfully' });
});

// Order history
app.get('/orders', authenticate, (req, res) => {
  const userOrders = lodash.filter(orders, { userId: req.user.userId });
  res.json({ orders: userOrders });
});

// Admin: all orders
app.get('/admin/orders', authenticate, (req, res) => {
  const summary = lodash.merge({}, { orders, totalRevenue: lodash.sumBy(orders, 'total') });
  res.json(summary);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date() });
});

// ── Static Files (MUST be after all API routes) ────────────────────────────────
// Serves the shopping UI at /shop  →  http://localhost:3000/shop
// Placed last so it never intercepts the API routes above.
app.use('/shop', express.static(path.join(__dirname, 'public')));

// ── Start ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🛒  VulnShop running!`);
    console.log(`    API  → http://localhost:${PORT}/`);
    console.log(`    Shop → http://localhost:${PORT}/shop`);
    console.log(`⚠️   Uses intentionally vulnerable dependencies for demo purposes.\n`);
  });
}

module.exports = app;
