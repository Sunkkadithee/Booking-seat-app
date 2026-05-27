const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const SECRET = "library_secret_key";

app.use(cors());
app.use(bodyParser.json());

// ✅ serve frontend
app.use(express.static(path.join(__dirname, "../frontend")));

// DB
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "library_app"
});

db.connect(() => console.log("MySQL connected"));

/* ================= REGISTER ================= */
app.post("/register", (req, res) => {
  const { first_name, last_name, email, password, student_id } = req.body;

  const sql = `
    INSERT INTO users (first_name, last_name, email, password, student_id)
    VALUES (?, ?, ?, ?, ?)
  `;

  db.query(sql, [first_name, last_name, email, password, student_id], (err) => {
    if (err) return res.status(400).json({ message: "User exists" });

    res.json({ message: "Register success" });
  });
});

/* ================= LOGIN ================= */
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ? OR student_id = ?";

  db.query(sql, [email, email], (err, results) => {
    if (err) return res.status(500).json({ message: "Server error" });
    if (results.length === 0) return res.status(401).json({ message: "User not found" });

    const user = results[0];

    if (user.password !== password)
      return res.status(401).json({ message: "Wrong password" });

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name
      },
      SECRET,
      { expiresIn: "1h" }
    );

    res.json({ message: "Login success", token });
  });
});

/* ================= DASHBOARD ================= */
app.get("/dashboard", (req, res) => {
  const token = req.headers.authorization;

  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, SECRET);

    db.query(
      "SELECT id, first_name, last_name, email FROM users WHERE id = ?",
      [decoded.id],
      (err, results) => {
        if (err) return res.status(500).json({ message: "DB error" });

        res.json({ user: results[0] });
      }
    );
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
});

/* ================= DISTANCE ================= */
function distance(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * Math.PI / 180) *
    Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) ** 2;

  return 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)) * R;
}

/* ================= BOOK SEAT ================= */
app.post("/book-seat", (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: "No token" });

  let decoded;
  try {
    decoded = jwt.verify(token, SECRET);
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }

  const { seat_id, activity, lat, lng } = req.body;

  const campusLat = 13.651;
  const campusLng = 100.494;

  const dist = distance(lat, lng, campusLat, campusLng);

  if (dist > 10) {
    return res.status(400).json({ message: "Too far from campus" });
  }

  db.query(
    "INSERT INTO bookings (user_id, seat_id, activity, user_lat, user_lng) VALUES (?,?,?,?,?)",
    [decoded.id, seat_id, activity, lat, lng],
    (err) => {
      if (err) return res.status(500).json({ message: "Booking error" });

      db.query("UPDATE seats SET status='booked' WHERE id=?", [seat_id]);

      res.json({ message: "Seat booked successfully" });
    }
  );
});

/* ================= START ================= */
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});