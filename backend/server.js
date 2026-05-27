const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const axios = require("axios");

const app = express();
const SECRET = "library_secret_key";

// Put your Hugging Face token here
const HF_TOKEN = "xhf_xUzCWhHchEityqUHEAhLEaDsAKFmytkiXF";

app.use(cors());
app.use(bodyParser.json());

app.use(express.static(path.join(__dirname, "../frontend")));

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

function isStrongPassword(password) {
  const passwordRule =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/;

  return passwordRule.test(password);
}

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

function allowRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied" });
    }

    next();
  };
}

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

app.post("/forgot-password", async (req, res) => {
  const { email, student_id, password } = req.body;

  if (!email || !student_id || !password) {
    return res.status(400).json({ message: "Please fill all fields" });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({
      message:
        "Password must be at least 8 characters and include uppercase, lowercase, number, and special character"
    });
  }

  db.query(
    "SELECT * FROM users WHERE email = ? AND student_id = ?",
    [email, student_id],
    async (err, results) => {
      if (err) return res.status(500).json({ message: "Server error" });

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
            return res.status(500).json({ message: "Password reset error" });
          }

          if (result.affectedRows === 0) {
            return res.status(400).json({ message: "Password not updated" });
          }

          res.json({ message: "Password reset success" });
        }
      );
    }
  );
});

app.post("/ask-ai", async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.json({ reply: "Please type a question." });
    }

    const response = await axios.post(
      "https://api-inference.huggingface.co/models/google/flan-t5-base",
      {
        inputs: `Answer as a KMUTT library assistant: ${message}`
      },
      {
        headers: {
          Authorization: `Bearer ${HF_TOKEN}`,
          "Content-Type": "application/json"
        }
      }
    );

    console.log("HF RESPONSE:", response.data);

    let reply = "";

    if (Array.isArray(response.data)) {
      reply = response.data[0].generated_text;
    } else if (response.data.generated_text) {
      reply = response.data.generated_text;
    } else if (response.data.error) {
      reply = response.data.error;
    } else {
      reply = "Sorry, I could not answer that.";
    }

    res.json({ reply: reply });

  } catch (err) {
    console.log("AI ERROR:", err.response?.data || err.message);

    res.status(500).json({
      reply: "AI server error. Check backend terminal."
    });
  }
});

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

app.get("/admin/users", verifyToken, allowRoles("admin"), (req, res) => {
  db.query(
    "SELECT id, first_name, last_name, email, student_id, role FROM users",
    (err, results) => {
      if (err) return res.status(500).json({ message: "DB error" });

      res.json({ users: results });
    }
  );
});

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

app.post("/check-in", verifyToken, (req, res) => {
  const { student_id, lat, lng } = req.body;

  if (!student_id || !lat || !lng) {
    return res.status(400).json({ message: "Missing check-in information" });
  }

  const libraryLat = 13.6510;
  const libraryLng = 100.4940;

  const dist = distance(lat, lng, libraryLat, libraryLng);

  if (dist > 0.2) {
    return res.status(400).json({
      message: "You are not at the library location"
    });
  }

  const sql = `
    SELECT bookings.id
    FROM bookings
    JOIN users ON bookings.user_id = users.id
    WHERE users.student_id = ?
    AND bookings.checked_in = false
    ORDER BY bookings.id DESC
    LIMIT 1
  `;

  db.query(sql, [student_id], (err, results) => {
    if (err) return res.status(500).json({ message: "Database error" });

    if (results.length === 0) {
      return res.status(404).json({
        message: "No active booking found for this Student ID"
      });
    }

    const bookingId = results[0].id;

    db.query(
      "UPDATE bookings SET checked_in = true, checked_in_at = NOW() WHERE id = ?",
      [bookingId],
      (err) => {
        if (err) return res.status(500).json({ message: "Check-in error" });

        res.json({ message: "Check-in success" });
      }
    );
  });
});
 

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});