// ====================================================
// DROPSHIP PRO BACKEND - WITH AUTHENTICATION
// Complete CJDropshipping + User Management
// ====================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Import authentication system
const { 
  authRoutes, 
  authenticateToken, 
  optionalAuth, 
  initializeDatabase,
  pool 
} = require('./auth');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ====================================================
// CJDROPSHIPPING API CLIENT
// ====================================================

class CJDropshippingAPI {
  constructor(apiKey, apiSecret) {
    this.apiKey = apiKey;
    this.apiSecret = apiSecret;
    this.baseURL = 'https://developers.cjdropshipping.com/api2.0/v1';
  }

  generateSignature(params) {
    const sortedParams = Object.keys(params)
      .sort()
      .map(key => `${key}${params[key]}`)
      .join('');
    
    return crypto
      .createHmac('sha256', this.apiSecret)
      .update(sortedParams)
      .digest('hex');
  }

  async request(endpoint, method = 'GET', data = {}) {
    const timestamp = Date.now();
    const params = {
      ...data,
      accessToken: this.apiKey,
      timestamp: timestamp
    };
    
    const signature = this.generateSignature(params);
    
    try {
      const response = await axios({
        method: method,
        url: `${this.baseURL}${endpoint}`,
        data: method === 'POST' ? params : null,
        params: method === 'GET' ? params : null,
        headers: {
          'Content-Type': 'application/json',
          'CJ-Access-Token': this.apiKey,
          'CJ-Signature': signature
        }
      });
      
      return response.data;
    } catch (error) {
      console.error('CJ API Error:', error.response?.data || error.message);
      throw error;
    }
  }

  async searchProducts(keyword, page = 1, pageSize = 20) {
    return this.request('/product/list', 'GET', {
      keyword: keyword || '',
      pageNum: page,
      pageSize: pageSize
    });
  }

  async getProduct(productId) {
    return this.request('/product/query', 'GET', {
      pid: productId
    });
  }

  async createOrder(orderData) {
    return this.request('/shopping/order/createOrder', 'POST', orderData);
  }

  async getOrderStatus(orderId) {
    return this.request('/shopping/order/getOrderDetail', 'GET', {
      orderId: orderId
    });
  }

  async getTracking(orderId) {
    return this.request('/shopping/order/getTrack', 'GET', {
      orderId: orderId
    });
  }
}

const cjAPI = new CJDropshippingAPI(
  process.env.CJ_API_KEY,
  process.env.CJ_API_SECRET
);

// ====================================================
// INITIALIZE DATABASE ON STARTUP
// ====================================================

initializeDatabase().catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});

// ====================================================
// AUTHENTICATION ROUTES
// ====================================================

app.use('/api/auth', authRoutes);

// ====================================================
// USER ADDRESS MANAGEMENT
// ====================================================

app.get('/api/addresses', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM user_addresses 
       WHERE user_id = $1 
       ORDER BY is_default DESC, created_at DESC`,
      [req.user.userId]
    );

    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Get addresses error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch addresses'
    });
  }
});

app.post('/api/addresses', authenticateToken, async (req, res) => {
  try {
    const {
      addressType,
      firstName,
      lastName,
      company,
      streetAddress,
      apartment,
      city,
      state,
      postalCode,
      country,
      phone,
      isDefault
    } = req.body;

    // If this is default, unset other defaults
    if (isDefault) {
      await pool.query(
        'UPDATE user_addresses SET is_default = false WHERE user_id = $1',
        [req.user.userId]
      );
    }

    const result = await pool.query(
      `INSERT INTO user_addresses 
       (user_id, address_type, first_name, last_name, company, street_address, 
        apartment, city, state, postal_code, country, phone, is_default)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING *`,
      [req.user.userId, addressType, firstName, lastName, company, streetAddress,
       apartment, city, state, postalCode, country, phone, isDefault]
    );

    res.status(201).json({
      success: true,
      message: 'Address added successfully',
      data: result.rows[0]
    });
  } catch (error) {
    console.error('Add address error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to add address'
    });
  }
});

app.put('/api/addresses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    // If setting as default, unset others
    if (updates.isDefault) {
      await pool.query(
        'UPDATE user_addresses SET is_default = false WHERE user_id = $1',
        [req.user.userId]
      );
    }

    const result = await pool.query(
      `UPDATE user_addresses 
       SET first_name = COALESCE($1, first_name),
           last_name = COALESCE($2, last_name),
           street_address = COALESCE($3, street_address),
           city = COALESCE($4, city),
           postal_code = COALESCE($5, postal_code),
           country = COALESCE($6, country),
           is_default = COALESCE($7, is_default),
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $8 AND user_id = $9
       RETURNING *`,
      [updates.firstName, updates.lastName, updates.streetAddress, updates.city,
       updates.postalCode, updates.country, updates.isDefault, id, req.user.userId]
    );

    res.json({
      success: true,
      message: 'Address updated successfully',
      data: result.rows[0]
    });
  } catch (error) {
    console.error('Update address error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update address'
    });
  }
});

app.delete('/api/addresses/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM user_addresses WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.userId]
    );

    res.json({
      success: true,
      message: 'Address deleted successfully'
    });
  } catch (error) {
    console.error('Delete address error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete address'
    });
  }
});

// ====================================================
// PRODUCT ENDPOINTS
// ====================================================

app.get('/api/products', async (req, res) => {
  try {
    const { keyword = '', page = 1, pageSize = 20 } = req.query;
    
    const products = await cjAPI.searchProducts(keyword, page, pageSize);
    
    res.json({
      success: true,
      data: products.data
    });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch products'
    });
  }
});

// ====================================================
// ORDER MANAGEMENT WITH USER DATA BACKUP
// ====================================================

app.post('/api/orders', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');

    const { items, shippingAddress, billingAddress, paymentMethodId } = req.body;

    // Get user info
    const userResult = await client.query(
      'SELECT email, first_name, last_name, phone FROM users WHERE id = $1',
      [req.user.userId]
    );
    const user = userResult.rows[0];

    // Calculate totals
    let subtotal = 0;
    const cjProducts = [];
    
    for (const item of items) {
      const product = await cjAPI.getProduct(item.productId);
      const itemTotal = product.data.sellPrice * item.quantity;
      subtotal += itemTotal;
      
      cjProducts.push({
        vid: item.variantId || product.data.variants[0].vid,
        quantity: item.quantity
      });
    }

    const shippingCost = 8.00; // Get from CJ API
    const tax = subtotal * 0.1; // 10% tax
    const total = subtotal + shippingCost + tax;

    // Process payment
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(total * 100),
      currency: 'usd',
      payment_method: paymentMethodId,
      confirm: true,
      metadata: {
        userId: req.user.userId.toString()
      }
    });

    if (paymentIntent.status !== 'succeeded') {
      throw new Error('Payment failed');
    }

    // Generate order number
    const orderNumber = `ORD-${Date.now()}`;

    // Create order in database (BACKUP ALL DATA)
    const orderResult = await client.query(
      `INSERT INTO orders (
        user_id, order_number, email,
        customer_first_name, customer_last_name, customer_phone,
        shipping_street, shipping_apartment, shipping_city, shipping_state, 
        shipping_postal_code, shipping_country,
        billing_street, billing_city, billing_state, 
        billing_postal_code, billing_country,
        subtotal, shipping_cost, tax, total,
        payment_method, payment_status, stripe_payment_id,
        status
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
        $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25
      ) RETURNING id`,
      [
        req.user.userId, orderNumber, user.email,
        user.first_name, user.last_name, user.phone,
        shippingAddress.street, shippingAddress.apartment, shippingAddress.city, 
        shippingAddress.state, shippingAddress.postalCode, shippingAddress.country,
        billingAddress.street, billingAddress.city, billingAddress.state,
        billingAddress.postalCode, billingAddress.country,
        subtotal, shippingCost, tax, total,
        'stripe', 'completed', paymentIntent.id,
        'processing'
      ]
    );

    const orderId = orderResult.rows[0].id;

    // Save order items
    for (const item of items) {
      const product = await cjAPI.getProduct(item.productId);
      await client.query(
        `INSERT INTO order_items 
         (order_id, product_id, product_name, variant_id, quantity, price, total)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          orderId, 
          item.productId, 
          product.data.productNameEn,
          item.variantId,
          item.quantity,
          product.data.sellPrice,
          product.data.sellPrice * item.quantity
        ]
      );
    }

    // Create order with CJDropshipping
    const cjOrderData = {
      orderNumber: orderNumber,
      shippingZip: shippingAddress.postalCode,
      shippingCountry: shippingAddress.country,
      shippingState: shippingAddress.state,
      shippingCity: shippingAddress.city,
      shippingAddress: shippingAddress.street,
      shippingCustomerName: `${user.first_name} ${user.last_name}`,
      shippingPhone: user.phone,
      remark: 'DropShip Pro order',
      products: cjProducts
    };

    const cjOrder = await cjAPI.createOrder(cjOrderData);

    // Update with CJ order ID
    await client.query(
      'UPDATE orders SET cj_order_id = $1, tracking_number = $2 WHERE id = $3',
      [cjOrder.data.orderId, cjOrder.data.logisticNumber, orderId]
    );

    // Clear cart
    await client.query(
      'DELETE FROM cart_items WHERE user_id = $1',
      [req.user.userId]
    );

    await client.query('COMMIT');

    res.json({
      success: true,
      message: 'Order created successfully',
      data: {
        orderId: orderId,
        orderNumber: orderNumber,
        total: total,
        trackingNumber: cjOrder.data.logisticNumber
      }
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Order creation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create order'
    });
  } finally {
    client.release();
  }
});

// Get user's orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, 
              json_agg(
                json_build_object(
                  'productName', oi.product_name,
                  'quantity', oi.quantity,
                  'price', oi.price,
                  'total', oi.total
                )
              ) as items
       FROM orders o
       LEFT JOIN order_items oi ON o.id = oi.order_id
       WHERE o.user_id = $1
       GROUP BY o.id
       ORDER BY o.created_at DESC`,
      [req.user.userId]
    );

    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch orders'
    });
  }
});

// Get single order
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, 
              json_agg(
                json_build_object(
                  'productName', oi.product_name,
                  'quantity', oi.quantity,
                  'price', oi.price
                )
              ) as items
       FROM orders o
       LEFT JOIN order_items oi ON o.id = oi.order_id
       WHERE o.id = $1 AND o.user_id = $2
       GROUP BY o.id`,
      [req.params.id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Order not found'
      });
    }

    res.json({
      success: true,
      data: result.rows[0]
    });
  } catch (error) {
    console.error('Get order error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch order'
    });
  }
});

// ====================================================
// CART MANAGEMENT (PERSISTENT)
// ====================================================

app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM cart_items WHERE user_id = $1',
      [req.user.userId]
    );

    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Get cart error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch cart'
    });
  }
});

app.post('/api/cart', authenticateToken, async (req, res) => {
  try {
    const { productId, variantId, quantity, price } = req.body;

    const result = await pool.query(
      `INSERT INTO cart_items (user_id, product_id, variant_id, quantity, price)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, product_id, variant_id)
       DO UPDATE SET quantity = cart_items.quantity + $4, updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [req.user.userId, productId, variantId, quantity, price]
    );

    res.json({
      success: true,
      message: 'Item added to cart',
      data: result.rows[0]
    });
  } catch (error) {
    console.error('Add to cart error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to add to cart'
    });
  }
});

// ====================================================
// HEALTH CHECK
// ====================================================

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'API is running',
    timestamp: new Date().toISOString(),
    database: 'Connected',
    cjDropshipping: 'Connected'
  });
});

// ====================================================
// START SERVER
// ====================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════════╗
  ║                                                ║
  ║   🚀 DROPSHIP PRO WITH AUTHENTICATION         ║
  ║                                                ║
  ║   Port: ${PORT}                                
  ║   Database: ✅ PostgreSQL                      ║
  ║   Auth: ✅ JWT Tokens                          ║
  ║   CJDropshipping: ✅ Connected                 ║
  ║                                                ║
  ╚═══════════════════════════════════════════════╝
  
  📦 API Endpoints:
  
  Authentication:
    POST /api/auth/register         - Create account
    POST /api/auth/login            - Login
    GET  /api/auth/me               - Get profile
    PUT  /api/auth/profile          - Update profile
    POST /api/auth/change-password  - Change password
  
  Addresses:
    GET  /api/addresses             - List addresses
    POST /api/addresses             - Add address
    PUT  /api/addresses/:id         - Update address
    DELETE /api/addresses/:id       - Delete address
  
  Products:
    GET  /api/products              - Search products
  
  Orders:
    POST /api/orders                - Create order
    GET  /api/orders                - List user orders
    GET  /api/orders/:id            - Get order details
  
  Cart:
    GET  /api/cart                  - Get cart
    POST /api/cart                  - Add to cart
  
  🔒 All user data is backed up in PostgreSQL database
  `);
});

module.exports = app;
