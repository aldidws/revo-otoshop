
require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const pool = require("./db");

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

// Membuat slug dari nama (contoh: "Oli Mesin" -> "oli-mesin")
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

// Daftar kategori (publik). Default hanya yang aktif; admin bisa ?all=true
app.get("/categories", async (req, res) => {
  try {
    const showAll = req.query.all === "true";
    const result = await pool.query(
      `SELECT id, name, slug, description, image_url, is_active, created_at
       FROM categories
       ${showAll ? "" : "WHERE is_active = true"}
       ORDER BY name ASC`
    );
    res.json({ categories: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Detail kategori (publik)
app.get("/categories/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "ID tidak valid" });
    }

    const result = await pool.query(
      `SELECT id, name, slug, description, image_url, is_active, created_at
       FROM categories WHERE id = $1`,
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Kategori tidak ditemukan" });
    }

    res.json({ category: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Validasi payload kategori
function validateCategory(body) {
  const { name, slug, description, image_url, is_active } = body ?? {};

  if (typeof name !== "string" || !name.trim() || name.trim().length > 100) {
    return { error: "Nama kategori tidak valid" };
  }
  if (slug !== undefined && (typeof slug !== "string" || slug.length > 120)) {
    return { error: "Slug tidak valid" };
  }
  if (description !== undefined && description !== null && typeof description !== "string") {
    return { error: "Deskripsi tidak valid" };
  }
  if (image_url !== undefined && image_url !== null && typeof image_url !== "string") {
    return { error: "image_url tidak valid" };
  }
  if (is_active !== undefined && typeof is_active !== "boolean") {
    return { error: "is_active harus boolean" };
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

// Buat kategori (admin)
app.post("/categories", authenticate, adminOnly, async (req, res) => {
  try {
    const { error, value } = validateCategory(req.body);
    if (error) return res.status(400).json({ message: error });

    const result = await pool.query(
      `INSERT INTO categories (name, slug, description, image_url, is_active)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, slug, description, image_url, is_active, created_at`,
      [value.name, value.slug, value.description, value.image_url, value.is_active]
    );

    res.status(201).json({
      message: "Kategori dibuat",
      category: result.rows[0],
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "Nama atau slug kategori sudah ada" });
    }
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Perbarui kategori (admin)
app.put("/categories/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "ID tidak valid" });
    }

    const { error, value } = validateCategory(req.body);
    if (error) return res.status(400).json({ message: error });

    const result = await pool.query(
      `UPDATE categories
       SET name = $1, slug = $2, description = $3, image_url = $4, is_active = $5
       WHERE id = $6
       RETURNING id, name, slug, description, image_url, is_active, created_at`,
      [value.name, value.slug, value.description, value.image_url, value.is_active, id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Kategori tidak ditemukan" });
    }

    res.json({ message: "Kategori diperbarui", category: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "Nama atau slug kategori sudah ada" });
    }
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Hapus kategori (admin)
app.delete("/categories/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "ID tidak valid" });
    }

    const result = await pool.query(
      `DELETE FROM categories WHERE id = $1 RETURNING id`,
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Kategori tidak ditemukan" });
    }

    res.json({ message: "Kategori dihapus" });
  } catch (error) {
    if (error.code === "23503") {
      return res.status(409).json({
        message: "Kategori masih dipakai produk, tidak bisa dihapus",
      });
    }
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

/* ======================= PRODUCTS ======================= */

// Daftar produk (publik). Filter: ?category_id= ?q= ?featured=true ?all=true
app.get("/products", async (req, res) => {
  try {
    const conditions = [];
    const params = [];

    // Secara default hanya tampilkan produk aktif
    if (req.query.all !== "true") {
      conditions.push(`p.is_active = true`);
    }

    if (req.query.category_id !== undefined) {
      const categoryId = Number(req.query.category_id);
      if (!Number.isInteger(categoryId) || categoryId < 1) {
        return res.status(400).json({ message: "category_id tidak valid" });
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
        `(p.name ILIKE $${params.length} OR p.brand ILIKE $${params.length} OR p.sku ILIKE $${params.length})`
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
      params
    );

    res.json({ products: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Detail produk (publik)
app.get("/products/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "ID tidak valid" });
    }

    const result = await pool.query(
      `SELECT p.id, p.sku, p.name, p.brand, p.description, p.price, p.stock,
              p.image_url, p.is_featured, p.is_active,
              p.category_id, c.name AS category_name,
              p.created_at, p.updated_at
       FROM products p
       LEFT JOIN categories c ON c.id = p.category_id
       WHERE p.id = $1`,
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Produk tidak ditemukan" });
    }

    res.json({ product: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Validasi payload produk
function validateProduct(body) {
  const {
    sku, name, brand, description, price, stock,
    image_url, is_featured, is_active, category_id,
  } = body ?? {};

  if (typeof sku !== "string" || !sku.trim() || sku.trim().length > 100) {
    return { error: "SKU tidak valid" };
  }
  if (typeof name !== "string" || !name.trim() || name.trim().length > 150) {
    return { error: "Nama produk tidak valid" };
  }
  if (typeof brand !== "string" || !brand.trim() || brand.trim().length > 100) {
    return { error: "Brand tidak valid" };
  }
  if (description !== undefined && description !== null && typeof description !== "string") {
    return { error: "Deskripsi tidak valid" };
  }
  if (typeof price !== "number" || !Number.isFinite(price) || price < 0) {
    return { error: "Harga tidak valid" };
  }
  if (stock !== undefined && (!Number.isInteger(stock) || stock < 0)) {
    return { error: "Stok tidak valid" };
  }
  if (image_url !== undefined && image_url !== null && typeof image_url !== "string") {
    return { error: "image_url tidak valid" };
  }
  if (is_featured !== undefined && typeof is_featured !== "boolean") {
    return { error: "is_featured harus boolean" };
  }
  if (is_active !== undefined && typeof is_active !== "boolean") {
    return { error: "is_active harus boolean" };
  }
  // category_id boleh berupa number atau numeric-string (id DB bertipe bigint)
  let categoryId = null;
  if (category_id !== undefined && category_id !== null && category_id !== "") {
    categoryId = Number(category_id);
    if (!Number.isInteger(categoryId) || categoryId < 1) {
      return { error: "category_id tidak valid" };
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

// Buat produk (admin)
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
        value.sku, value.name, value.brand, value.description, value.price,
        value.stock, value.image_url, value.is_featured, value.is_active,
        value.category_id,
      ]
    );

    res.status(201).json({ message: "Produk dibuat", product: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "SKU produk sudah ada" });
    }
    if (error.code === "23503") {
      return res.status(400).json({ message: "Kategori tidak ditemukan" });
    }
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Perbarui produk (admin)
app.put("/products/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "ID tidak valid" });
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
        value.sku, value.name, value.brand, value.description, value.price,
        value.stock, value.image_url, value.is_featured, value.is_active,
        value.category_id, id,
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Produk tidak ditemukan" });
    }

    res.json({ message: "Produk diperbarui", product: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "SKU produk sudah ada" });
    }
    if (error.code === "23503") {
      return res.status(400).json({ message: "Kategori tidak ditemukan" });
    }
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Hapus produk (admin)
app.delete("/products/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "ID tidak valid" });
    }

    const result = await pool.query(
      `DELETE FROM products WHERE id = $1 RETURNING id`,
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Produk tidak ditemukan" });
    }

    res.json({ message: "Produk dihapus" });
  } catch (error) {
    if (error.code === "23503") {
      return res.status(409).json({
        message: "Produk tidak bisa dihapus karena sudah ada di pesanan",
      });
    }
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

/* ======================= ORDERS ======================= */

// Membuat nomor pesanan unik, contoh: ORD-20261009-AB12CD
function generateOrderNumber() {
  const d = new Date();
  const ymd =
    d.getFullYear().toString() +
    String(d.getMonth() + 1).padStart(2, "0") +
    String(d.getDate()).padStart(2, "0");
  const rand = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `ORD-${ymd}-${rand}`;
}

// Daftar pesanan: customer lihat miliknya sendiri, admin lihat semua
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
      isAdmin ? [] : [req.user.id]
    );

    res.json({ orders: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Detail pesanan beserta item-nya
app.get("/orders/:id", authenticate, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "ID tidak valid" });
    }

    const orderResult = await pool.query(
      `SELECT id, order_number, user_id, status,
              subtotal, shipping_cost, discount, total,
              recipient_name, recipient_phone,
              shipping_address, shipping_city, shipping_province,
              shipping_postal_code, customer_note,
              created_at, updated_at
       FROM orders WHERE id = $1`,
      [id]
    );

    if (!orderResult.rowCount) {
      return res.status(404).json({ message: "Pesanan tidak ditemukan" });
    }

    const order = orderResult.rows[0];

    // Customer hanya boleh melihat pesanannya sendiri
    if (
      req.user.role !== "admin" &&
      Number(order.user_id) !== Number(req.user.id)
    ) {
      return res.status(403).json({ message: "Akses ditolak" });
    }

    const itemsResult = await pool.query(
      `SELECT id, product_id, product_name, product_sku,
              unit_price, quantity, line_total
       FROM order_items
       WHERE order_id = $1
       ORDER BY id ASC`,
      [id]
    );

    res.json({ order: { ...order, items: itemsResult.rows } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

// Buat pesanan dari daftar item; stok dicek & dikurangi dalam transaksi
app.post("/orders", authenticate, async (req, res) => {
  const body = req.body ?? {};
  const { items, shipping } = body;

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ message: "Pesanan harus memiliki minimal 1 item" });
  }

  // Validasi data pengiriman (wajib sesuai skema)
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
      return res.status(400).json({ message: `Data pengiriman '${key}' wajib diisi` });
    }
  }

  const shippingCost = Number(ship.shipping_cost ?? 0);
  const discount = Number(ship.discount ?? 0);
  if (!Number.isFinite(shippingCost) || shippingCost < 0) {
    return res.status(400).json({ message: "shipping_cost tidak valid" });
  }
  if (!Number.isFinite(discount) || discount < 0) {
    return res.status(400).json({ message: "discount tidak valid" });
  }
  const customerNote =
    typeof ship.customer_note === "string" ? ship.customer_note : null;

  // Validasi item dan gabungkan kuantitas produk yang sama
  const quantityByProduct = new Map();
  for (const item of items) {
    const productId = Number(item?.product_id);
    const quantity = Number(item?.quantity);
    if (!Number.isInteger(productId) || productId < 1) {
      return res.status(400).json({ message: "product_id tidak valid" });
    }
    if (!Number.isInteger(quantity) || quantity < 1) {
      return res.status(400).json({ message: "quantity tidak valid" });
    }
    quantityByProduct.set(
      productId,
      (quantityByProduct.get(productId) ?? 0) + quantity
    );
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Kunci baris produk agar stok konsisten saat permintaan bersamaan
    const productIds = [...quantityByProduct.keys()];
    const productResult = await client.query(
      `SELECT id, sku, name, price, stock, is_active
       FROM products
       WHERE id = ANY($1::bigint[])
       FOR UPDATE`,
      [productIds]
    );

    if (productResult.rowCount !== productIds.length) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Ada produk yang tidak ditemukan" });
    }

    let subtotal = 0;
    const orderItems = [];
    for (const product of productResult.rows) {
      const quantity = quantityByProduct.get(Number(product.id));
      if (!product.is_active) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          message: `Produk "${product.name}" tidak tersedia`,
        });
      }
      if (product.stock < quantity) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          message: `Stok tidak cukup untuk produk "${product.name}"`,
        });
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

    const total = subtotal + shippingCost - discount;
    if (total < 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Total pesanan tidak boleh negatif" });
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
        req.user.id,
        subtotal.toFixed(2),
        shippingCost.toFixed(2),
        discount.toFixed(2),
        total.toFixed(2),
        requiredShip.recipient_name.trim(),
        requiredShip.recipient_phone.trim(),
        requiredShip.shipping_address.trim(),
        requiredShip.shipping_city.trim(),
        requiredShip.shipping_province.trim(),
        requiredShip.shipping_postal_code.trim(),
        customerNote,
      ]
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
        ]
      );
      createdItems.push(itemResult.rows[0]);

      await client.query(
        `UPDATE products SET stock = stock - $1, updated_at = now() WHERE id = $2`,
        [item.quantity, item.productId]
      );
    }

    await client.query("COMMIT");

    res.status(201).json({
      message: "Pesanan dibuat",
      order: { ...order, items: createdItems },
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    if (error.code === "23505") {
      return res.status(409).json({ message: "Nomor pesanan bentrok, coba lagi" });
    }
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  } finally {
    client.release();
  }
});

// Perbarui status pesanan (admin)
app.patch("/orders/:id/status", authenticate, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { status } = req.body ?? {};
    const allowed = ["pending", "paid", "shipped", "completed", "cancelled"];

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: "ID tidak valid" });
    }
    if (!allowed.includes(status)) {
      return res.status(400).json({
        message: `Status harus salah satu dari: ${allowed.join(", ")}`,
      });
    }

    const result = await pool.query(
      `UPDATE orders SET status = $1 WHERE id = $2
       RETURNING id, user_id, status, total, created_at`,
      [status, id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: "Pesanan tidak ditemukan" });
    }

    res.json({ message: "Status pesanan diperbarui", order: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`API berjalan di port ${PORT}`);
});