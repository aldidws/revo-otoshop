
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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`API berjalan di port ${PORT}`);
});