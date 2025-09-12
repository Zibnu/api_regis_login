import express from "express";
import jwt from "jsonwebtoken";
import bcypt from "bcrypt";
import psql from "pg";

const { Pool } = psql;
const app = express();
app.use(express.json());

const SEKRET_KEYS = "learnJwt";

// Konfigurasi Koneksi Postgresql
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "all_user",
  password: "zibnu",
  port: 5432,
});

// endpoint welcome
app.get("/", (req, res) => {
  res.json({
    message: "Server Is running",
    available_endpoint: ["POST/regis", "POST/login", ""],
  });
});

// registrasi
app.post("/regis", async (req, res) => {
  try {
    const { user_name, password } = req.body;

    // Validasi input
    if (!user_name && !password) {
      return res
        .status(400)
        .json({ message: "Username and Password REQUIRED!!" });
    }
    // VALIDASI User (Jika user sudah ada)
    const checkUserQuery = "SELECT * FROM userss WHERE user_name = $1";
    const checkResult = await pool.query(checkUserQuery, [user_name]);
    if (checkResult.rows.length > 0) {
      return res.status(400).json({ message: "Username alredy exits" });
    }

    // hash password
    const hashPassword = await bcypt.hash(password, 10);

    // simpan ke database postgresql
    const query =
      "INSERT INTO userss (user_name, password) VALUES ($1, $2) RETURNING id, user_name";
    const values = [user_name, hashPassword];
    const result = await pool.query(query, values);

    res.status(201).json({
      message: "User sukses to add",
      user: result.rows[0],
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(400).json({ error: "username alredy exists" });
    }
    console.error("Registration Error", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { user_name, password } = req.body;

    // Validasi input
    if (!user_name && !password) {
      return res
        .status(400)
        .json({ message: "Username & Password REQUIRED!!!!" });
    }

    // Cari user di database
    const query = "SELECT * FROM userss WHERE user_name = $1";
    const result = await pool.query(query, [user_name]);

    if (result.rows.length < 0) {
      return res.status(400).json({ massage: "NOT FOUND !!!" });
    }

    const user = result.rows[0];

    // Cek Password dengan bcrypt Compare
    const isMatch = await bcypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Password Salah" });
    }

    // TOKEN JWT
    const token = jwt.sign(
      { id: user.id, user_name: user.user_name }, // payload
      SEKRET_KEYS, //Kode rahasia
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login Sukses",
      token,
    });
  } catch {
    console.error("LOGIN ERROR", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

//MiddleWare cek JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; //ambil setelah barrier

  if (!token) return res.status(401).json({ message: "token not found!!" });

  jwt.verify(token, SEKRET_KEYS, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid Token" });
    req.user = user; //menyimpan data payload ke req user
    next();
  });
}

// ROUTE PROTECTED
app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: `Hello ${req.user.user_name}, ini adalah bagian profile`,
    data: req.user,
  });
});

// GET ALL users
app.get("/users", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, user_name FROM userss ORDER BY id"
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error("error fetching user", err);
    res.status(500).json({ error: "Internal Server error" });
  }
});

app.listen(600, () => console.log("PPQ "));
