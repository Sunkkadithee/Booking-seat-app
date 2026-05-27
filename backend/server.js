const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const SECRET = "library_secret_key";
const nodemailer = require("nodemailer");

app.use(cors());
app.use(bodyParser.json());

// Serve frontend
app.use(express.static(path.join(__dirname, "../frontend")));

// DB
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "library_app"
});

db.connect((err) => {
  if (err) {
    console.log("MySQL connection error:", err);
    return;
  }
  console.log("MySQL connected");
});

/* ================= PASSWORD RULE ================= */
function isStrongPassword(password) {
  const passwordRule =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/;

  return passwordRule.test(password);
}

/* ================= TOKEN MIDDLEWARE ================= */
function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "No token" });
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

/* ================= ROLE MIDDLEWARE ================= */
function allowRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied" });
    }

    next();
  };
}

/* ================= REGISTER ================= */
app.post("/register", async (req, res) => {
  const { first_name, last_name, email, password, student_id } = req.body;

  if (!first_name || !last_name || !email || !password || !student_id) {
    return res.status(400).json({ message: "Please fill all fields" });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({
      message:
        "Password must be at least 8 characters and include uppercase, lowercase, number, and special character"
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO users 
      (first_name, last_name, email, password, student_id, role)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [first_name, last_name, email, hashedPassword, student_id, "user"],
      (err) => {
        if (err) {
          return res.status(400).json({ message: "User already exists" });
        }

        res.json({ message: "Register success" });
      }
    );
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* ================= LOGIN ================= */
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Please enter email and password" });
  }

  const sql = "SELECT * FROM users WHERE email = ? OR student_id = ?";

  db.query(sql, [email, email], async (err, results) => {
    if (err) return res.status(500).json({ message: "Server error" });

    if (results.length === 0) {
      return res.status(401).json({ message: "User not found" });
    }

    const user = results[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Wrong password" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role
      },
      SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login success",
      token: token,
      role: user.role
    });
  });
});

/* ================= forgot-password ================= */

app.post("/forgot-password", async (req, res) => {
  const { email, student_id, password } = req.body;

  console.log("RESET REQUEST:", email, student_id);

  if (!email || !student_id || !password) {
    return res.status(400).json({ message: "Please fill all fields" });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({
      message: "Password must be at least 8 characters and include uppercase, lowercase, number, and special character"
    });
  }

  db.query(
    "SELECT * FROM users WHERE email = ? AND student_id = ?",
    [email, student_id],
    async (err, results) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "Server error" });
      }

      console.log("MATCHED USERS:", results.length);

      if (results.length === 0) {
        return res.status(404).json({
          message: "Email and Student ID do not match"
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      db.query(
        "UPDATE users SET password = ? WHERE email = ? AND student_id = ?",
        [hashedPassword, email, student_id],
        (err, result) => {
          if (err) {
            console.log(err);
            return res.status(500).json({ message: "Password reset error" });
          }

          console.log("UPDATED ROWS:", result.affectedRows);

          if (result.affectedRows === 0) {
            return res.status(400).json({ message: "Password not updated" });
          }

          res.json({ message: "Password reset success" });
        }
      );
    }
  );
});

/* ================= DASHBOARD ================= */
app.get("/dashboard", verifyToken, (req, res) => {
  db.query(
    "SELECT id, first_name, last_name, email, student_id, role FROM users WHERE id = ?",
    [req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ message: "DB error" });

      if (results.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({ user: results[0] });
    }
  );
});

/* ================= ADMIN: GET ALL USERS ================= */
app.get("/admin/users", verifyToken, allowRoles("admin"), (req, res) => {
  db.query(
    "SELECT id, first_name, last_name, email, student_id, role FROM users",
    (err, results) => {
      if (err) return res.status(500).json({ message: "DB error" });

      res.json({ users: results });
    }
  );
});

/* ================= ADMIN: CHANGE USER ROLE ================= */
app.put("/admin/users/:id/role", verifyToken, allowRoles("admin"), (req, res) => {
  const { role } = req.body;
  const userId = req.params.id;

  if (!["admin", "user"].includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }

  db.query(
    "UPDATE users SET role = ? WHERE id = ?",
    [role, userId],
    (err) => {
      if (err) return res.status(500).json({ message: "Update role error" });

      res.json({ message: "User role updated" });
    }
  );
});

/* ================= DISTANCE ================= */
function distance(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) ** 2;

  return 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)) * R;
}

/* ================= BOOK SEAT ================= */
app.post("/book-seat", verifyToken, allowRoles("user", "admin"), (req, res) => {
  const { seat_id, activity, lat, lng } = req.body;

  if (!seat_id || !activity || !lat || !lng) {
    return res.status(400).json({ message: "Missing booking information" });
  }

  const campusLat = 13.651;
  const campusLng = 100.494;

  const dist = distance(lat, lng, campusLat, campusLng);

  if (dist > 10) {
    return res.status(400).json({ message: "Too far from campus" });
  }

  db.query(
    "INSERT INTO bookings (user_id, seat_id, activity, user_lat, user_lng) VALUES (?, ?, ?, ?, ?)",
    [req.user.id, seat_id, activity, lat, lng],
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