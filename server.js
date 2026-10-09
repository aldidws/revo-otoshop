
require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const pool = require("./db");
const express = require("express");
const jwt = require("jsonwebtoken");
const pool = require("./db");
const cookieParser = require("cookie-parser");

app.use(cookieParser());

const app = express();

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
}));
app.use(express.json());

// Tangani body JSON yang tidak valid tanpa membocorkan stack trace
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({
      message: "Body permintaan harus berupa JSON yang valid",
    });
  }
  next(err);
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || !process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL dan JWT_SECRET wajib diisi");
}

// Membuat token autentikasi
function createToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "1d" }
  );
}

// Middleware untuk memeriksa token
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      message: "Silakan login terlebih dahulu",
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      message: "Token tidak valid atau kedaluwarsa",
    });
  }
}

// Middleware khusus admin
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Akses khusus admin",
    });
  }

  next();
}

// Halaman dasar API
app.get("/", (req, res) => {
  res.json({ message: "Auth API berjalan" });
});

// REGISTER: semua pendaftar menjadi customer
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body ?? {};

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
        message: "Data tidak valid. Password harus 8-72 byte.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, password, role)
       VALUES ($1, $2, $3, 'customer')
       RETURNING id, name, email, role`,
      [name.trim(), normalizedEmail, hashedPassword]
    );

    const user = result.rows[0];

    return res.status(201).json({
      message: "Registrasi berhasil",
      user,
      token: createToken(user),
      redirect: "/",
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        message: "Email sudah terdaftar",
      });
    }

    console.error(error);
    return res.status(500).json({
      message: "Terjadi kesalahan pada server",
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
        message: "Email atau password tidak valid",
      });
    }

    const result = await pool.query(
      `SELECT id, name, email, password, role
       FROM users WHERE email = $1`,
      [email.trim().toLowerCase()]
    );

    const user = result.rows[0];

    if (
      !user ||
      !(await bcrypt.compare(password, user.password))
    ) {
      return res.status(401).json({
        message: "Email atau password salah",
      });
    }

    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    return res.json({
      message: "Login berhasil",
      user: safeUser,
      token: createToken(safeUser),
      redirect:
        safeUser.role === "admin" ? "/dashboard" : "/",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "Terjadi kesalahan pada server",
    });
  }
});

// Identitas pengguna yang sedang login
app.get("/me", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, role
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        message: "Akun tidak ditemukan",
      });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Kesalahan server" });
  }
});

// Endpoint yang hanya boleh diakses admin
app.get("/admin", authenticate, adminOnly, (req, res) => {
  res.json({ message: "Selamat datang, Admin!" });
});


/* =========================================
   AUTHENTICATION MIDDLEWARE
   Mendukung JWT cookie atau Bearer token
========================================= */

function authenticateToken(req, res, next) {
  const cookieToken = req.cookies?.token;

  const authHeader = req.headers.authorization;
  const bearerToken = authHeader?.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;

  const token = cookieToken || bearerToken;

  if (!token) {
    return res.status(401).json({
      message: "Silakan login terlebih dahulu.",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Token tidak valid atau sudah kedaluwarsa.",
    });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      message: "Akses hanya untuk admin.",
    });
  }

  next();
}

/* =========================================
   GET /products
   Katalog produk publik
========================================= */

app.get("/products", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        p.id,
        p.sku,
        p.name,
        p.brand,
        p.description,
        p.price,
        p.stock,
        p.image_url,
        p.is_featured,
        p.category_id,
        c.name AS category_name,
        c.slug AS category_slug
      FROM products p
      LEFT JOIN categories c ON c.id = p.category_id
      WHERE p.is_active = TRUE
        AND (c.id IS NULL OR c.is_active = TRUE)
      ORDER BY p.is_featured DESC, p.created_at DESC
    `);

    res.json({
      success: true,
      count: result.rows.length,
      products: result.rows,
    });
  } catch (error) {
    console.error("GET /products:", error.message);

    res.status(500).json({
      success: false,
      message: "Gagal mengambil katalog produk.",
    });
  }
});

/* =========================================
   GET /products/:id
   Detail satu produk
========================================= */

app.get("/products/:id", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        p.*,
        c.name AS category_name,
        c.slug AS category_slug
      FROM products p
      LEFT JOIN categories c ON c.id = p.category_id
      WHERE p.id = $1
        AND p.is_active = TRUE
        AND (c.id IS NULL OR c.is_active = TRUE)
      `,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Produk tidak ditemukan.",
      });
    }

    res.json({
      success: true,
      product: result.rows[0],
    });
  } catch (error) {
    console.error("GET /products/:id:", error.message);

    res.status(500).json({
      success: false,
      message: "Gagal mengambil detail produk.",
    });
  }
});

/* =========================================
   GET /categories
   Daftar kategori publik
========================================= */

app.get("/categories", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        c.id,
        c.name,
        c.slug,
        c.description,
        c.image_url,
        COUNT(p.id)::INTEGER AS product_count
      FROM categories c
      LEFT JOIN products p
        ON p.category_id = c.id
        AND p.is_active = TRUE
      WHERE c.is_active = TRUE
      GROUP BY c.id
      ORDER BY c.name ASC
    `);

    res.json({
      success: true,
      count: result.rows.length,
      categories: result.rows,
    });
  } catch (error) {
    console.error("GET /categories:", error.message);

    res.status(500).json({
      success: false,
      message: "Gagal mengambil kategori.",
    });
  }
});

/* =========================================
   GET /orders
   Customer: pesanan miliknya sendiri
   Admin: semua pesanan
========================================= */

app.get("/orders", authenticateToken, async (req, res) => {
  try {
    const isAdmin = req.user.role === "admin";

    const query = `
      SELECT
        o.id,
        o.order_number,
        o.user_id,
        o.status,
        o.subtotal,
        o.shipping_cost,
        o.discount,
        o.total,
        o.created_at,
        COALESCE(
          jsonb_agg(
            jsonb_build_object(
              'id', oi.id,
              'product_id', oi.product_id,
              'product_name', oi.product_name,
              'product_sku', oi.product_sku,
              'unit_price', oi.unit_price,
              'quantity', oi.quantity,
              'line_total', oi.line_total
            )
          ) FILTER (WHERE oi.id IS NOT NULL),
          '[]'::jsonb
        ) AS items
      FROM orders o
      LEFT JOIN order_items oi ON oi.order_id = o.id
      ${isAdmin ? "" : "WHERE o.user_id = $1"}
      GROUP BY o.id
      ORDER BY o.created_at DESC
    `;

    const params = isAdmin ? [] : [req.user.id];
    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      orders: result.rows,
    });
  } catch (error) {
    console.error("GET /orders:", error.message);

    res.status(500).json({
      success: false,
      message: "Gagal mengambil pesanan.",
    });
  }
});

/* =========================================
   GET /admin/orders
   Contoh endpoint khusus admin
========================================= */

app.get(
  "/admin/orders",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          order_number,
          user_id,
          status,
          subtotal,
          shipping_cost,
          discount,
          total,
          created_at
        FROM orders
        ORDER BY created_at DESC
      `);

      res.json({
        success: true,
        count: result.rows.length,
        orders: result.rows,
      });
    } catch (error) {
      console.error("GET /admin/orders:", error.message);

      res.status(500).json({
        success: false,
        message: "Gagal mengambil pesanan admin.",
      });
    }
  }
);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`API berjalan di port ${PORT}`);
});