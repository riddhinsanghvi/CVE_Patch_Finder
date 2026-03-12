const request = require('supertest');
const app     = require('../server');

describe('VulnShop API', () => {

  describe('GET /', () => {
    it('returns all products', async () => {
      const res = await request(app).get('/');
      expect(res.status).toBe(200);
      expect(res.body.products).toHaveLength(6);
      expect(res.body.categories).toBeDefined();
    });

    it('filters by search term', async () => {
      const res = await request(app).get('/?search=laptop');
      expect(res.status).toBe(200);
      expect(res.body.products[0].name).toMatch(/Laptop/i);
    });

    it('filters by category', async () => {
      const res = await request(app).get('/?category=Electronics');
      expect(res.status).toBe(200);
      expect(res.body).toBeDefined();
      expect(Array.isArray(res.body.products)).toBe(true);
      expect(res.body.products.length).toBeGreaterThan(0);
      res.body.products.forEach(p => expect(p.category).toBe('Electronics'));
    });
  });

  describe('GET /products/:id', () => {
    it('returns a product by id', async () => {
      const res = await request(app).get('/products/1');
      expect(res.status).toBe(200);
      expect(res.body.product.id).toBe(1);
    });

    it('returns 404 for unknown id', async () => {
      const res = await request(app).get('/products/9999');
      expect(res.status).toBe(404);
    });
  });

  describe('POST /auth/register', () => {
    it('registers a new user', async () => {
      const res = await request(app).post('/auth/register').send({
        username: 'testuser', email: 'test@test.com', password: 'password123',
      });
      expect(res.status).toBe(201);
      expect(res.body.token).toBeDefined();
    });

    it('rejects duplicate email', async () => {
      await request(app).post('/auth/register').send({
        username: 'u2', email: 'dup@test.com', password: 'pass',
      });
      const res = await request(app).post('/auth/register').send({
        username: 'u3', email: 'dup@test.com', password: 'pass',
      });
      expect(res.status).toBe(409);
    });
  });

  describe('GET /health', () => {
    it('returns ok', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });
  });
});
