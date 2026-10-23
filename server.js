require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const pool = require("./db");

const app = express();

app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
  }),
);
app.use(express.json());

// Handle invalid JSON bodies without leaking a stack trace
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({
      message: "Request body must be valid JSON",
    });
  }
  next(err);
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || !process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL and JWT_SECRET are required");
}

// Create an authentication token
function createToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: "1d",
  });
}

// Middleware to verify the token
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({
      message: "Please log in first",
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      message: "Invalid or expired token",
    });
  }
}

// Admin-only middleware
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Admin access only",
    });
  }

  next();
}

// API base endpoint
app.get("/", (req, res) => {
  res.json({ message: "Auth API is running" });
});

// About endpoint (public): basic service info
app.get("/about", (req, res) => {
  res.json({
    name: "Revo OtoShop Auth API",
    description:
      "Authentication and store API for Revo OtoShop (users, categories, products, orders).",
    version: require("./package.json").version,
    environment: process.env.NODE_ENV || "development",
  });
});

// REGISTER: every new sign-up becomes a customer
app.post("/register", async (req, res) => {
  try {
    const body = req.body ?? {};
    const { name, email, password } = body;
    // Accept either snake_case or camelCase from the client
    const confirmPassword = body.confirm_password ?? body.confirmPassword;

    if (
      typeof name !== "string" ||
      !name.trim() ||
      name.trim().length > 100 ||
      typeof email !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      email.length > 255 ||
      typeof password !== "string" ||
      password.length < 8 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        message: "Invalid data. Password must be 8-72 bytes.",
      });
    }

    if (typeof confirmPassword !== "string" || confirmPassword !== password) {
      return res.status(400).json({
        message: "Password confirmation does not match",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, password, role)
       VALUES ($1, $2, $3, 'customer')
       RETURNING id, name, email, role`,
      [name.trim(), normalizedEmail, hashedPassword],
    );

    const user = result.rows[0];

    return res.status(201).json({
      message: "Registration successful",
      user,
      token: createToken(user),
      redirect: "/",
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        message: "Email is already registered",
      });
    }

    console.error(error);
    return res.status(500).json({
      message: "A server error occurred",
    });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body ?? {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email.length > 255 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        message: "Invalid email or password",
      });
    }

    const result = await pool.query(
      `SELECT id, name, email, password, role
       FROM users WHERE email = $1`,
      [email.trim().toLowerCase()],
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        message: "Incorrect email or password",
      });
    }

    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    return res.json({
      message: "Login successful",
      user: safeUser,
      token: createToken(safeUser),
      redirect: safeUser.role === "admin" ? "/dashboard" : "/",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "A server error occurred",
    });
  }
});

// Identity of the currently logged-in user
app.get("/me", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, role
       FROM users WHERE id = $1`,
      [req.user.id],
    );

    if (!result.rowCount) {
      return res.status(401).json({
        message: "Account not found",
      });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Admin-only endpoint
app.get("/admin", authenticate, adminOnly, (req, res) => {
  res.json({ message: "Welcome, Admin!" });
});

// Admin dashboard summary (admin only)
app.get("/admin/dashboard", authenticate, adminOnly, async (req, res) => {
  try {
    const [
      userCount,
      categoryCount,
      productCount,
      orderStats,
      ordersByStatus,
      recentOrders,
      lowStock,
    ] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS total FROM users`),
      pool.query(`SELECT COUNT(*)::int AS total FROM categories`),
      pool.query(`SELECT COUNT(*)::int AS total FROM products`),
      pool.query(
        `SELECT COUNT(*)::int AS total_orders,
                COALESCE(SUM(total), 0) AS total_revenue
         FROM orders
         WHERE status <> 'cancelled'`,
      ),
      pool.query(
        `SELECT status, COUNT(*)::int AS total
         FROM orders
         GROUP BY status
         ORDER BY status ASC`,
      ),
      pool.query(
        `SELECT id, order_number, user_id, status, total, created_at
         FROM orders
         ORDER BY created_at DESC
         LIMIT 5`,
      ),
      pool.query(
        `SELECT id, sku, name, stock
         FROM products
         WHERE is_active = true AND stock <= 5
         ORDER BY stock ASC
         LIMIT 10`,
      ),
    ]);

    res.json({
      message: "Welcome to the admin dashboard",
      admin: { id: req.user.id, role: req.user.role },
      summary: {
        users: userCount.rows[0].total,
        categories: categoryCount.rows[0].total,
        products: productCount.rows[0].total,
        orders: orderStats.rows[0].total_orders,
        revenue: orderStats.rows[0].total_revenue,
      },
      orders_by_status: ordersByStatus.rows,
      recent_orders: recentOrders.rows,
      low_stock_products: lowStock.rows,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// DASHBOARD: admin summary (redirect target when an admin logs in)
app.get("/dashboard", authenticate, adminOnly, async (req, res) => {
  try {
    const [
      userCount,
      categoryCount,
      productCount,
      orderStats,
      ordersByStatus,
      recentOrders,
      lowStock,
    ] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS total FROM users`),
      pool.query(`SELECT COUNT(*)::int AS total FROM categories`),
      pool.query(`SELECT COUNT(*)::int AS total FROM products`),
      pool.query(
        `SELECT COUNT(*)::int AS total_orders,
                COALESCE(SUM(total), 0) AS total_revenue
         FROM orders
         WHERE status <> 'cancelled'`,
      ),
      pool.query(
        `SELECT status, COUNT(*)::int AS total
         FROM orders
         GROUP BY status
         ORDER BY status ASC`,
      ),
      pool.query(
        `SELECT id, order_number, user_id, status, total, created_at
         FROM orders
         ORDER BY created_at DESC
         LIMIT 5`,
      ),
      pool.query(
        `SELECT id, sku, name, stock
         FROM products
         WHERE is_active = true AND stock <= 5
         ORDER BY stock ASC
         LIMIT 10`,
      ),
    ]);

    res.json({
      message: "Welcome to the admin dashboard",
      admin: { id: req.user.id, role: req.user.role },
      summary: {
        users: userCount.rows[0].total,
        categories: categoryCount.rows[0].total,
        products: productCount.rows[0].total,
        orders: orderStats.rows[0].total_orders,
        revenue: orderStats.rows[0].total_revenue,
      },
      orders_by_status: ordersByStatus.rows,
      recent_orders: recentOrders.rows,
      low_stock_products: lowStock.rows,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Build a slug from a name (e.g. "Engine Oil" -> "engine-oil")
function slugify(text) {
  return text
    .toString()
    .normalize("NFKD")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/[\s_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/* ======================= CATEGORIES ======================= */

// List categories (public). Defaults to active only; admin can use ?all=true
app.get("/categories", async (req, res) => {
  try {
    const showAll = req.query.all === "true";
    const result = await pool.query(
      `SELECT id, name, slug, description, image_url, is_active, created_at
       FROM categories
       ${showAll ? "" : "WHERE is_active = true"}
       ORDER BY name ASC`,
    );
    res.json({ categories: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Category detail (public)
app.get("/categories/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const result = await pool.query(
      `SELECT id, name, slug, description, image_url, is_active, created_at
       FROM categories WHERE id = $1`,
      [id],
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Category not found" });
    }

    res.json({ category: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Validate category payload
function validateCategory(body) {
  const { name, slug, description, image_url, is_active } = body ?? {};

  if (typeof name !== "string" || !name.trim() || name.trim().length > 100) {
    return { error: "Invalid category name" };
  }
  if (slug !== undefined && (typeof slug !== "string" || slug.length > 120)) {
    return { error: "Invalid slug" };
  }
  if (
    description !== undefined &&
    description !== null &&
    typeof description !== "string"
  ) {
    return { error: "Invalid description" };
  }
  if (
    image_url !== undefined &&
    image_url !== null &&
    typeof image_url !== "string"
  ) {
    return { error: "Invalid image_url" };
  }
  if (is_active !== undefined && typeof is_active !== "boolean") {
    return { error: "is_active must be a boolean" };
  }

  const finalName = name.trim();
  return {
    value: {
      name: finalName,
      slug: slug && slug.trim() ? slugify(slug) : slugify(finalName),
      description: typeof description === "string" ? description : null,
      image_url: typeof image_url === "string" ? image_url : null,
      is_active: typeof is_active === "boolean" ? is_active : true,
    },
  };
}

// Create category (admin)
app.post("/categories", authenticate, adminOnly, async (req, res) => {
  try {
    const { error, value } = validateCategory(req.body);
    if (error) return res.status(400).json({ message: error });

    const result = await pool.query(
      `INSERT INTO categories (name, slug, description, image_url, is_active)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, slug, description, image_url, is_active, created_at`,
      [
        value.name,
        value.slug,
        value.description,
        value.image_url,
        value.is_active,
      ],
    );

    res.status(201).json({
      message: "Category created",
      category: result.rows[0],
    });
  } catch (error) {
    if (error.code === "23505") {
      return res
        .status(409)
        .json({ message: "Category name or slug already exists" });
    }
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Update category (admin)
app.put("/categories/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const { error, value } = validateCategory(req.body);
    if (error) return res.status(400).json({ message: error });

    const result = await pool.query(
      `UPDATE categories
       SET name = $1, slug = $2, description = $3, image_url = $4, is_active = $5
       WHERE id = $6
       RETURNING id, name, slug, description, image_url, is_active, created_at`,
      [
        value.name,
        value.slug,
        value.description,
        value.image_url,
        value.is_active,
        id,
      ],
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Category not found" });
    }

    res.json({ message: "Category updated", category: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res
        .status(409)
        .json({ message: "Category name or slug already exists" });
    }
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Delete category (admin)
app.delete("/categories/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const result = await pool.query(
      `DELETE FROM categories WHERE id = $1 RETURNING id`,
      [id],
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Category not found" });
    }

    res.json({ message: "Category deleted" });
  } catch (error) {
    if (error.code === "23503") {
      return res.status(409).json({
        message: "Category is still used by products and cannot be deleted",
      });
    }
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

/* ======================= PRODUCTS ======================= */

// List products (public). Filters: ?category_id= ?q= ?featured=true ?all=true
app.get("/products", async (req, res) => {
  try {
    const conditions = [];
    const params = [];

    // Show only active products by default
    if (req.query.all !== "true") {
      conditions.push(`p.is_active = true`);
    }

    if (req.query.category_id !== undefined) {
      const categoryId = Number(req.query.category_id);
      if (!Number.isInteger(categoryId) || categoryId < 1) {
        return res.status(400).json({ message: "Invalid category_id" });
      }
      params.push(categoryId);
      conditions.push(`p.category_id = $${params.length}`);
    }

    if (req.query.featured === "true") {
      conditions.push(`p.is_featured = true`);
    }

    if (typeof req.query.q === "string" && req.query.q.trim()) {
      params.push(`%${req.query.q.trim()}%`);
      conditions.push(
        `(p.name ILIKE $${params.length} OR p.brand ILIKE $${params.length} OR p.sku ILIKE $${params.length})`,
      );
    }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    const result = await pool.query(
      `SELECT p.id, p.sku, p.name, p.brand, p.description, p.price, p.stock,
              p.image_url, p.is_featured, p.is_active,
              p.category_id, c.name AS category_name,
              p.created_at, p.updated_at
       FROM products p
       LEFT JOIN categories c ON c.id = p.category_id
       ${where}
       ORDER BY p.created_at DESC`,
      params,
    );

    res.json({ products: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Product detail (public)
app.get("/products/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const result = await pool.query(
      `SELECT p.id, p.sku, p.name, p.brand, p.description, p.price, p.stock,
              p.image_url, p.is_featured, p.is_active,
              p.category_id, c.name AS category_name,
              p.created_at, p.updated_at
       FROM products p
       LEFT JOIN categories c ON c.id = p.category_id
       WHERE p.id = $1`,
      [id],
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json({ product: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Validate product payload
function validateProduct(body) {
  const {
    sku,
    name,
    brand,
    description,
    price,
    stock,
    image_url,
    is_featured,
    is_active,
    category_id,
  } = body ?? {};

  if (typeof sku !== "string" || !sku.trim() || sku.trim().length > 100) {
    return { error: "Invalid SKU" };
  }
  if (typeof name !== "string" || !name.trim() || name.trim().length > 150) {
    return { error: "Invalid product name" };
  }
  if (typeof brand !== "string" || !brand.trim() || brand.trim().length > 100) {
    return { error: "Invalid brand" };
  }
  if (
    description !== undefined &&
    description !== null &&
    typeof description !== "string"
  ) {
    return { error: "Invalid description" };
  }
  if (typeof price !== "number" || !Number.isFinite(price) || price < 0) {
    return { error: "Invalid price" };
  }
  if (stock !== undefined && (!Number.isInteger(stock) || stock < 0)) {
    return { error: "Invalid stock" };
  }
  if (
    image_url !== undefined &&
    image_url !== null &&
    typeof image_url !== "string"
  ) {
    return { error: "Invalid image_url" };
  }
  if (is_featured !== undefined && typeof is_featured !== "boolean") {
    return { error: "is_featured must be a boolean" };
  }
  if (is_active !== undefined && typeof is_active !== "boolean") {
    return { error: "is_active must be a boolean" };
  }
  // category_id may be a number or a numeric string (DB id is bigint)
  let categoryId = null;
  if (category_id !== undefined && category_id !== null && category_id !== "") {
    categoryId = Number(category_id);
    if (!Number.isInteger(categoryId) || categoryId < 1) {
      return { error: "Invalid category_id" };
    }
  }

  return {
    value: {
      sku: sku.trim(),
      name: name.trim(),
      brand: brand.trim(),
      description: typeof description === "string" ? description : null,
      price,
      stock: Number.isInteger(stock) ? stock : 0,
      image_url: typeof image_url === "string" ? image_url : null,
      is_featured: typeof is_featured === "boolean" ? is_featured : false,
      is_active: typeof is_active === "boolean" ? is_active : true,
      category_id: categoryId,
    },
  };
}

// Create product (admin)
app.post("/products", authenticate, adminOnly, async (req, res) => {
  try {
    const { error, value } = validateProduct(req.body);
    if (error) return res.status(400).json({ message: error });

    const result = await pool.query(
      `INSERT INTO products
         (sku, name, brand, description, price, stock,
          image_url, is_featured, is_active, category_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id, sku, name, brand, description, price, stock,
                 image_url, is_featured, is_active, category_id,
                 created_at, updated_at`,
      [
        value.sku,
        value.name,
        value.brand,
        value.description,
        value.price,
        value.stock,
        value.image_url,
        value.is_featured,
        value.is_active,
        value.category_id,
      ],
    );

    res
      .status(201)
      .json({ message: "Product created", product: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "Product SKU already exists" });
    }
    if (error.code === "23503") {
      return res.status(400).json({ message: "Category not found" });
    }
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Update product (admin)
app.put("/products/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const { error, value } = validateProduct(req.body);
    if (error) return res.status(400).json({ message: error });

    const result = await pool.query(
      `UPDATE products
       SET sku = $1, name = $2, brand = $3, description = $4, price = $5,
           stock = $6, image_url = $7, is_featured = $8, is_active = $9,
           category_id = $10, updated_at = now()
       WHERE id = $11
       RETURNING id, sku, name, brand, description, price, stock,
                 image_url, is_featured, is_active, category_id,
                 created_at, updated_at`,
      [
        value.sku,
        value.name,
        value.brand,
        value.description,
        value.price,
        value.stock,
        value.image_url,
        value.is_featured,
        value.is_active,
        value.category_id,
        id,
      ],
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json({ message: "Product updated", product: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "Product SKU already exists" });
    }
    if (error.code === "23503") {
      return res.status(400).json({ message: "Category not found" });
    }
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Delete product (admin)
app.delete("/products/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const result = await pool.query(
      `DELETE FROM products WHERE id = $1 RETURNING id`,
      [id],
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json({ message: "Product deleted" });
  } catch (error) {
    if (error.code === "23503") {
      return res.status(409).json({
        message: "Product cannot be deleted because it is already in an order",
      });
    }
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

/* ======================= ORDERS ======================= */

// Generate a unique order number, e.g. ORD-20261009-AB12CD
function generateOrderNumber() {
  const d = new Date();
  const ymd =
    d.getFullYear().toString() +
    String(d.getMonth() + 1).padStart(2, "0") +
    String(d.getDate()).padStart(2, "0");
  const rand = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `ORD-${ymd}-${rand}`;
}

// List orders: customers see their own, admins see all
app.get("/orders", authenticate, async (req, res) => {
  try {
    const isAdmin = req.user.role === "admin";
    const result = await pool.query(
      `SELECT id, order_number, user_id, status,
              subtotal, shipping_cost, discount, total,
              recipient_name, recipient_phone,
              shipping_address, shipping_city, shipping_province,
              shipping_postal_code, customer_note,
              created_at, updated_at
       FROM orders
       ${isAdmin ? "" : "WHERE user_id = $1"}
       ORDER BY created_at DESC`,
      isAdmin ? [] : [req.user.id],
    );

    res.json({ orders: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Order detail including its items
app.get("/orders/:id", authenticate, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const orderResult = await pool.query(
      `SELECT id, order_number, user_id, status,
              subtotal, shipping_cost, discount, total,
              recipient_name, recipient_phone,
              shipping_address, shipping_city, shipping_province,
              shipping_postal_code, customer_note,
              created_at, updated_at
       FROM orders WHERE id = $1`,
      [id],
    );

    if (!orderResult.rowCount) {
      return res.status(404).json({ message: "Order not found" });
    }

    const order = orderResult.rows[0];

    // Customers may only view their own order
    if (
      req.user.role !== "admin" &&
      Number(order.user_id) !== Number(req.user.id)
    ) {
      return res.status(403).json({ message: "Access denied" });
    }

    const itemsResult = await pool.query(
      `SELECT id, product_id, product_name, product_sku,
              unit_price, quantity, line_total
       FROM order_items
       WHERE order_id = $1
       ORDER BY id ASC`,
      [id],
    );

    res.json({ order: { ...order, items: itemsResult.rows } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Validate + normalize shipping input shared by the checkout paths.
// Returns { error } on invalid input or { value } with trimmed fields + costs.
function parseShipping(shipping) {
  const ship = shipping ?? {};
  const requiredShip = {
    recipient_name: ship.recipient_name,
    recipient_phone: ship.recipient_phone,
    shipping_address: ship.shipping_address,
    shipping_city: ship.shipping_city,
    shipping_province: ship.shipping_province,
    shipping_postal_code: ship.shipping_postal_code,
  };
  for (const [key, val] of Object.entries(requiredShip)) {
    if (typeof val !== "string" || !val.trim()) {
      return { error: `Shipping field '${key}' is required` };
    }
  }

  const shippingCost = Number(ship.shipping_cost ?? 0);
  const discount = Number(ship.discount ?? 0);
  if (!Number.isFinite(shippingCost) || shippingCost < 0) {
    return { error: "Invalid shipping_cost" };
  }
  if (!Number.isFinite(discount) || discount < 0) {
    return { error: "Invalid discount" };
  }

  return {
    value: {
      recipient_name: requiredShip.recipient_name.trim(),
      recipient_phone: requiredShip.recipient_phone.trim(),
      shipping_address: requiredShip.shipping_address.trim(),
      shipping_city: requiredShip.shipping_city.trim(),
      shipping_province: requiredShip.shipping_province.trim(),
      shipping_postal_code: requiredShip.shipping_postal_code.trim(),
      shipping_cost: shippingCost,
      discount,
      customer_note:
        typeof ship.customer_note === "string" ? ship.customer_note : null,
    },
  };
}

// Typed error so callers can map a failure to the right HTTP status.
class OrderError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Core order-creation logic shared by the explicit-items and cart checkout paths.
// Runs inside the caller's transaction using an already-connected `client`:
// locks product rows FOR UPDATE, validates found/active/stock, computes totals,
// inserts the order + its items, and decrements stock. Throws OrderError on a
// business-rule failure (the caller rolls back and maps status/message).
async function createOrderFromQuantities(
  client,
  userId,
  quantityByProduct,
  shipping,
) {
  const productIds = [...quantityByProduct.keys()];
  const productResult = await client.query(
    `SELECT id, sku, name, price, stock, is_active
     FROM products
     WHERE id = ANY($1::bigint[])
     FOR UPDATE`,
    [productIds],
  );

  if (productResult.rowCount !== productIds.length) {
    throw new OrderError(400, "Some products were not found");
  }

  let subtotal = 0;
  const orderItems = [];
  for (const product of productResult.rows) {
    const quantity = quantityByProduct.get(Number(product.id));
    if (!product.is_active) {
      throw new OrderError(409, `Product "${product.name}" is not available`);
    }
    if (product.stock < quantity) {
      throw new OrderError(
        409,
        `Insufficient stock for product "${product.name}"`,
      );
    }
    const unitPrice = Number(product.price);
    const lineTotal = unitPrice * quantity;
    subtotal += lineTotal;
    orderItems.push({
      productId: Number(product.id),
      productName: product.name,
      productSku: product.sku,
      unitPrice,
      quantity,
      lineTotal,
    });
  }

  const total = subtotal + shipping.shipping_cost - shipping.discount;
  if (total < 0) {
    throw new OrderError(400, "Order total cannot be negative");
  }

  const orderResult = await client.query(
    `INSERT INTO orders
       (order_number, user_id, status, subtotal, shipping_cost, discount, total,
        recipient_name, recipient_phone, shipping_address, shipping_city,
        shipping_province, shipping_postal_code, customer_note)
     VALUES ($1, $2, 'pending', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
     RETURNING id, order_number, user_id, status, subtotal, shipping_cost,
               discount, total, recipient_name, recipient_phone,
               shipping_address, shipping_city, shipping_province,
               shipping_postal_code, customer_note, created_at, updated_at`,
    [
      generateOrderNumber(),
      userId,
      subtotal.toFixed(2),
      shipping.shipping_cost.toFixed(2),
      shipping.discount.toFixed(2),
      total.toFixed(2),
      shipping.recipient_name,
      shipping.recipient_phone,
      shipping.shipping_address,
      shipping.shipping_city,
      shipping.shipping_province,
      shipping.shipping_postal_code,
      shipping.customer_note,
    ],
  );
  const order = orderResult.rows[0];

  const createdItems = [];
  for (const item of orderItems) {
    const itemResult = await client.query(
      `INSERT INTO order_items
         (order_id, product_id, product_name, product_sku,
          unit_price, quantity, line_total)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, product_id, product_name, product_sku,
                 unit_price, quantity, line_total`,
      [
        order.id,
        item.productId,
        item.productName,
        item.productSku,
        item.unitPrice.toFixed(2),
        item.quantity,
        item.lineTotal.toFixed(2),
      ],
    );
    createdItems.push(itemResult.rows[0]);

    await client.query(
      `UPDATE products SET stock = stock - $1, updated_at = now() WHERE id = $2`,
      [item.quantity, item.productId],
    );
  }

  return { order, items: createdItems };
}

// Create an order; stock is checked and decremented in a transaction.
// Checkout approach: this single endpoint handles both sources. When the body
// has a non-empty `items` array the order is built from those explicit items
// (backward compatible). When `items` is absent/empty it falls back to the
// logged-in user's server-side cart and clears that cart in the same
// transaction on success.
app.post("/orders", authenticate, async (req, res) => {
  const body = req.body ?? {};
  const { items, shipping } = body;

  const { error: shippingError, value: parsedShipping } =
    parseShipping(shipping);
  if (shippingError) {
    return res.status(400).json({ message: shippingError });
  }

  const fromCart = !Array.isArray(items) || items.length === 0;

  // Build the per-product quantity map from explicit items (if provided).
  const quantityByProduct = new Map();
  if (!fromCart) {
    for (const item of items) {
      const productId = Number(item?.product_id);
      const quantity = Number(item?.quantity);
      if (!Number.isInteger(productId) || productId < 1) {
        return res.status(400).json({ message: "Invalid product_id" });
      }
      if (!Number.isInteger(quantity) || quantity < 1) {
        return res.status(400).json({ message: "Invalid quantity" });
      }
      quantityByProduct.set(
        productId,
        (quantityByProduct.get(productId) ?? 0) + quantity,
      );
    }
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Cart fallback: load the user's current cart lines when no explicit items.
    if (fromCart) {
      const cartItemsResult = await client.query(
        `SELECT product_id, quantity
         FROM cart_items
         WHERE user_id = $1
         ORDER BY id ASC`,
        [req.user.id],
      );

      if (!cartItemsResult.rowCount) {
        await client.query("ROLLBACK");
        return res.status(400).json({ message: "Your cart is empty" });
      }

      for (const row of cartItemsResult.rows) {
        quantityByProduct.set(
          Number(row.product_id),
          (quantityByProduct.get(Number(row.product_id)) ?? 0) +
            Number(row.quantity),
        );
      }
    }

    const { order, items: createdItems } = await createOrderFromQuantities(
      client,
      req.user.id,
      quantityByProduct,
      parsedShipping,
    );

    // Clear the user's cart within the same transaction when ordering from it.
    if (fromCart) {
      await client.query(
        `DELETE FROM cart_items WHERE user_id = $1`,
        [req.user.id],
      );
    }

    await client.query("COMMIT");

    res.status(201).json({
      message: "Order created",
      order: { ...order, items: createdItems },
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    if (error instanceof OrderError) {
      return res.status(error.status).json({ message: error.message });
    }
    if (error.code === "23505") {
      return res
        .status(409)
        .json({ message: "Order number conflict, please try again" });
    }
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  } finally {
    client.release();
  }
});

// Restore stock for every item of an order. Mirrors the checkout decrement in
// reverse: locks the order's product rows FOR UPDATE, then increments stock.
// Runs inside the caller's transaction using an already-connected `client`.
async function restoreOrderStock(client, orderId) {
  const itemsResult = await client.query(
    `SELECT product_id, quantity FROM order_items WHERE order_id = $1`,
    [orderId]
  );

  if (!itemsResult.rowCount) return;

  const productIds = itemsResult.rows.map((row) => Number(row.product_id));
  // Lock product rows so stock stays consistent under concurrent requests
  await client.query(
    `SELECT id FROM products WHERE id = ANY($1::bigint[]) FOR UPDATE`,
    [productIds]
  );

  for (const item of itemsResult.rows) {
    await client.query(
      `UPDATE products SET stock = stock + $1, updated_at = now() WHERE id = $2`,
      [item.quantity, item.product_id]
    );
  }
}

// Cancel an order (authenticated). Customers may only cancel their own order;
// admins may cancel any. Only "pending" or "paid" orders can be cancelled.
// Stock is restored for every item in the same transaction.
app.patch("/orders/:id/cancel", authenticate, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ message: "Invalid ID" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const orderResult = await client.query(
      `SELECT id, user_id, status FROM orders WHERE id = $1 FOR UPDATE`,
      [id]
    );

    if (!orderResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "Order not found" });
    }

    const order = orderResult.rows[0];

    // Customers may only cancel their own order
    if (
      req.user.role !== "admin" &&
      Number(order.user_id) !== Number(req.user.id)
    ) {
      await client.query("ROLLBACK");
      return res.status(403).json({ message: "Access denied" });
    }

    if (!["pending", "paid"].includes(order.status)) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        message: "Only pending or paid orders can be cancelled",
      });
    }

    await restoreOrderStock(client, id);

    const updatedResult = await client.query(
      `UPDATE orders SET status = 'cancelled', updated_at = now()
       WHERE id = $1
       RETURNING id, order_number, user_id, status,
                 subtotal, shipping_cost, discount, total,
                 recipient_name, recipient_phone,
                 shipping_address, shipping_city, shipping_province,
                 shipping_postal_code, customer_note,
                 created_at, updated_at`,
      [id]
    );

    const itemsResult = await client.query(
      `SELECT id, product_id, product_name, product_sku,
              unit_price, quantity, line_total
       FROM order_items
       WHERE order_id = $1
       ORDER BY id ASC`,
      [id]
    );

    await client.query("COMMIT");

    res.json({
      message: "Order cancelled",
      order: { ...updatedResult.rows[0], items: itemsResult.rows },
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  } finally {
    client.release();
  }
});

// Update order status (admin). Transitioning into "cancelled" from a
// non-cancelled state restores stock once, inside a transaction.
app.patch("/orders/:id/status", authenticate, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body ?? {};
  const allowed = ["pending", "paid", "shipped", "completed", "cancelled"];

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ message: "Invalid ID" });
  }
  if (!allowed.includes(status)) {
    return res.status(400).json({
      message: `Status must be one of: ${allowed.join(", ")}`,
    });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const currentResult = await client.query(
      `SELECT status FROM orders WHERE id = $1 FOR UPDATE`,
      [id]
    );

    if (!currentResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "Order not found" });
    }

    // Restore stock only when moving into "cancelled" from a non-cancelled
    // state; never double-restore an already-cancelled order.
    if (status === "cancelled" && currentResult.rows[0].status !== "cancelled") {
      await restoreOrderStock(client, id);
    }

    const result = await client.query(
      `UPDATE orders SET status = $1, updated_at = now() WHERE id = $2
       RETURNING id, user_id, status, total, created_at`,
      [status, id]
    );

    await client.query("COMMIT");

    res.json({ message: "Order status updated", order: result.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  } finally {
    client.release();
  }
});

/* ======================= CART ======================= */

// Build the cart response for a user: items joined to current product data
// plus a computed subtotal. Returns an empty cart (never 404) when the user
// has no items yet. Runs on the pool (no transaction) and is the single
// source of truth for the cart shape used by every cart endpoint.
// The cart is keyed directly by user_id on cart_items (one cart per user).
async function getCartResponse(userId) {
  const itemsResult = await pool.query(
    `SELECT p.id AS product_id, p.name, p.sku, p.price, p.stock,
            p.image_url, p.is_active, ci.quantity
     FROM cart_items ci
     JOIN products p ON p.id = ci.product_id
     WHERE ci.user_id = $1
     ORDER BY ci.id ASC`,
    [userId]
  );

  let subtotal = 0;
  const items = itemsResult.rows.map((row) => {
    const price = Number(row.price);
    const lineTotal = price * row.quantity;
    subtotal += lineTotal;
    return {
      product_id: Number(row.product_id),
      name: row.name,
      sku: row.sku,
      price: row.price,
      stock: row.stock,
      image_url: row.image_url,
      is_active: row.is_active,
      quantity: row.quantity,
      line_total: lineTotal.toFixed(2),
    };
  });

  return { items, subtotal: subtotal.toFixed(2) };
}

// Get the logged-in user's cart
app.get("/cart", authenticate, async (req, res) => {
  try {
    res.json(await getCartResponse(req.user.id));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Add a product to the cart (adds to the existing quantity if already present)
app.post("/cart/items", authenticate, async (req, res) => {
  try {
    const body = req.body ?? {};
    const productId = Number(body.product_id);
    const quantity = Number(body.quantity);

    if (!Number.isInteger(productId) || productId < 1) {
      return res.status(400).json({ message: "Invalid product_id" });
    }
    if (!Number.isInteger(quantity) || quantity < 1) {
      return res.status(400).json({ message: "Invalid quantity" });
    }

    const productResult = await pool.query(
      `SELECT id, name, stock, is_active FROM products WHERE id = $1`,
      [productId]
    );

    if (!productResult.rowCount) {
      return res.status(404).json({ message: "Product not found" });
    }

    const product = productResult.rows[0];
    if (!product.is_active) {
      return res.status(409).json({ message: "Product is not available" });
    }

    // Check the prospective resulting quantity against stock BEFORE mutating,
    // so no rollback is needed on the pool connection.
    const existingResult = await pool.query(
      `SELECT quantity FROM cart_items WHERE user_id = $1 AND product_id = $2`,
      [req.user.id, productId]
    );
    const existingQuantity = existingResult.rowCount
      ? existingResult.rows[0].quantity
      : 0;

    if (existingQuantity + quantity > product.stock) {
      return res.status(409).json({
        message: "Requested quantity exceeds available stock",
      });
    }

    await pool.query(
      `INSERT INTO cart_items (user_id, product_id, quantity)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, product_id)
       DO UPDATE SET quantity = cart_items.quantity + EXCLUDED.quantity,
                     updated_at = now()`,
      [req.user.id, productId, quantity]
    );

    res.json(await getCartResponse(req.user.id));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Set the absolute quantity of a product in the cart
app.patch("/cart/items/:productId", authenticate, async (req, res) => {
  try {
    const productId = Number(req.params.productId);
    if (!Number.isInteger(productId) || productId < 1) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const quantity = Number((req.body ?? {}).quantity);
    if (!Number.isInteger(quantity) || quantity < 1) {
      return res.status(400).json({ message: "Invalid quantity" });
    }

    const lineResult = await pool.query(
      `SELECT quantity FROM cart_items WHERE user_id = $1 AND product_id = $2`,
      [req.user.id, productId]
    );

    if (!lineResult.rowCount) {
      return res.status(404).json({ message: "Item not in cart" });
    }

    const stockResult = await pool.query(
      `SELECT stock FROM products WHERE id = $1`,
      [productId]
    );
    const stock = stockResult.rowCount ? stockResult.rows[0].stock : 0;
    if (quantity > stock) {
      return res.status(409).json({
        message: "Requested quantity exceeds available stock",
      });
    }

    await pool.query(
      `UPDATE cart_items SET quantity = $1, updated_at = now()
       WHERE user_id = $2 AND product_id = $3`,
      [quantity, req.user.id, productId]
    );

    res.json(await getCartResponse(req.user.id));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Remove a single product line from the cart
app.delete("/cart/items/:productId", authenticate, async (req, res) => {
  try {
    const productId = Number(req.params.productId);
    if (!Number.isInteger(productId) || productId < 1) {
      return res.status(400).json({ message: "Invalid ID" });
    }

    const result = await pool.query(
      `DELETE FROM cart_items
       WHERE user_id = $1 AND product_id = $2
       RETURNING id`,
      [req.user.id, productId]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Item not in cart" });
    }

    res.json(await getCartResponse(req.user.id));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

// Clear all items from the cart
app.delete("/cart", authenticate, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM cart_items WHERE user_id = $1`,
      [req.user.id]
    );

    res.json(await getCartResponse(req.user.id));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "A server error occurred" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`API running on port ${PORT}`);
});
