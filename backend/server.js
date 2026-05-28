process.env.TZ = "Asia/Bangkok";
require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const multer = require("multer");
const fs = require("fs");

const app = express();

const SECRET = process.env.JWT_SECRET || "library_secret_key";
const PORT = process.env.PORT || 3000;
const LIBRARY = require("../map.js");

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "../frontend")));

app.get("/map.js", (req, res) => {
  res.sendFile(path.join(__dirname, "../map.js"));
});

const uploadDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

app.use("/uploads", express.static(uploadDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, "user-" + req.user.id + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: Number(process.env.MYSQLPORT || 3306),
  timezone: "+07:00",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

db.getConnection((err, connection) => {
  if (err) {
    console.log("MySQL connection error:", err);
    return;
  }

  console.log("MySQL connected");
  connection.release();
});

function isStrongPassword(password) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/.test(password);
}

function verifyToken(req, res, next) {
  let token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "No token" });
  }

  if (token.startsWith("Bearer ")) {
    token = token.slice(7);
  }

  try {
    req.user = jwt.verify(token, SECRET);
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

function timeToMinutes(time) {
  const [h, m] = String(time).slice(0, 5).split(":").map(Number);
  return h * 60 + m;
}

function formatDateOnly(value) {
  if (value instanceof Date) return value.toISOString().split("T")[0];
  return String(value).split("T")[0];
}

function isWithinNext24Hours(bookingDate, startTime) {
  const now = new Date();
  const max = new Date(now.getTime() + 24 * 60 * 60 * 1000);
  const bookingStartText = bookingDate + "T" + String(startTime).slice(0, 5) + ":00+07:00";
  const bookingStart = new Date(bookingStartText);

  return bookingStart > now && bookingStart <= max;
}

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

function expireLateBookings(callback) {
  db.query(
    `
    DELETE FROM bookings
    WHERE checked_in = false
    AND CONCAT(booking_date, ' ', start_time) < NOW()
    AND TIMESTAMPDIFF(
      MINUTE,
      CONCAT(booking_date, ' ', start_time),
      NOW()
    ) > ?
    `,
    [LIBRARY.lateLimitMinutes],
    callback
  );
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

app.get("/index.html", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

app.get("/dashboard.html", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/dashboard.html"));
});

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

    db.query(
      `
      INSERT INTO users 
      (first_name, last_name, email, password, student_id, role)
      VALUES (?, ?, ?, ?, ?, ?)
      `,
      [first_name, last_name, email, hashedPassword, student_id, "user"],
      (err) => {
        if (err) {
          console.log(err);
          return res.status(400).json({ message: "User already exists" });
        }

        res.json({ message: "Register success" });
      }
    );
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Please enter email and password" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ? OR student_id = ?",
    [email, email],
    async (err, results) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "Server error" });
      }

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

      res.json({ message: "Login success", token, role: user.role });
    }
  );
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
        return res.status(404).json({ message: "Email and Student ID do not match" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      db.query(
        "UPDATE users SET password = ? WHERE email = ? AND student_id = ?",
        [hashedPassword, email, student_id],
        (err, result) => {
          if (err) return res.status(500).json({ message: "Password reset error" });
          if (result.affectedRows === 0) {
            return res.status(400).json({ message: "Password not updated" });
          }

          res.json({ message: "Password reset success" });
        }
      );
    }
  );
});

app.get("/dashboard", verifyToken, (req, res) => {
  db.query(
    "SELECT id, first_name, last_name, email, student_id, role, profile_image FROM users WHERE id = ?",
    [req.user.id],
    (err, results) => {
      if (err) {
      console.log("Dashboard DB error:", err);
      return res.status(500).json({ message: err.message });
    }
      if (results.length === 0) return res.status(404).json({ message: "User not found" });

      res.json({ user: results[0] });
    }
  );
});

app.post("/profile-picture", verifyToken, upload.single("profileImage"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No image uploaded" });
  }

  const imagePath = "/uploads/" + req.file.filename;

  db.query(
    "UPDATE users SET profile_image = ? WHERE id = ?",
    [imagePath, req.user.id],
    (err) => {
      if (err) return res.status(500).json({ message: "Profile image update error" });

      res.json({
        message: "Profile picture updated",
        profile_image: imagePath
      });
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

  if (!["admin", "user"].includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }

  db.query(
    "UPDATE users SET role = ? WHERE id = ?",
    [role, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ message: "Update role error" });
      res.json({ message: "User role updated" });
    }
  );
});

app.get("/check-in/bookings", verifyToken, (req, res) => {
  expireLateBookings((expireErr) => {
    if (expireErr) return res.status(500).json({ message: "Auto cancel error" });

    db.query(
      `
      SELECT id, seat_id, activity, booking_date, start_time, end_time, checked_in
      FROM bookings
      WHERE user_id = ?
      AND checked_in = false
      AND booking_date = DATE(CONVERT_TZ(NOW(), '+00:00', '+07:00'))
      AND CONCAT(booking_date, ' ', end_time) >= CONVERT_TZ(NOW(), '+00:00', '+07:00')
      ORDER BY start_time ASC
      `,
      [req.user.id],
      (err, results) => {
        if (err) return res.status(500).json({ message: "Booking list error" });

        res.json({
          bookings: results,
          library: {
            lat: LIBRARY.lat,
            lng: LIBRARY.lng,
            radius_meters: LIBRARY.checkInRadiusKm * 1000
          }
        });
      }
    );
  });
});

app.post("/check-in", verifyToken, (req, res) => {
  const { booking_id, student_id, lat, lng } = req.body;

  if (!booking_id || !student_id || lat === undefined || lng === undefined) {
    return res.status(400).json({ message: "Missing check-in information" });
  }

  const dist = distance(Number(lat), Number(lng), LIBRARY.lat, LIBRARY.lng);

  if (dist > LIBRARY.checkInRadiusKm) {
    return res.status(400).json({ message: "You are more than 500m away from the library" });
  }

  expireLateBookings((expireErr) => {
    if (expireErr) return res.status(500).json({ message: "Auto cancel error" });

    db.query(
      `
      SELECT bookings.*
      FROM bookings
      JOIN users ON bookings.user_id = users.id
      WHERE bookings.id = ?
      AND bookings.user_id = ?
      AND users.student_id = ?
      AND bookings.checked_in = false
      `,
      [booking_id, req.user.id, student_id],
      (err, results) => {
        if (err) return res.status(500).json({ message: "Database error" });

        if (results.length === 0) {
          return res.status(404).json({ message: "Booking not found or already cancelled" });
        }

        const booking = results[0];
        const dateOnly = formatDateOnly(booking.booking_date);
        const startOnly = String(booking.start_time).slice(0, 5);
        const startDateTime = new Date(`${dateOnly}T${startOnly}:00+07:00`);
        const now = new Date();

        const earliestCheckIn = new Date(
          startDateTime.getTime() - LIBRARY.earlyCheckInMinutes * 60 * 1000
        );

        const latestCheckIn = new Date(
          startDateTime.getTime() + LIBRARY.lateLimitMinutes * 60 * 1000
        );

        if (now < earliestCheckIn) {
          return res.status(400).json({
            message: "You can check in only 30 minutes before your booking starts"
          });
        }

        if (now > latestCheckIn) {
          db.query(
            "DELETE FROM bookings WHERE id = ? AND user_id = ?",
            [booking_id, req.user.id],
            () => {
              return res.status(400).json({
                message: "You are more than 15 minutes late. Booking cancelled."
              });
            }
          );
          return;
        }

        db.query(
          "UPDATE bookings SET checked_in = true, checked_in_at = NOW() WHERE id = ? AND user_id = ?",
          [booking_id, req.user.id],
          (err) => {
            if (err) return res.status(500).json({ message: "Check-in error" });
            res.json({ message: "Check-in success" });
          }
        );
      }
    );
  });
});

app.get("/seats", verifyToken, (req, res) => {
  expireLateBookings((expireErr) => {
    if (expireErr) return res.status(500).json({ message: "Auto cancel error" });

    db.query("SELECT * FROM seats ORDER BY seat_id", (err, results) => {
      if (err) return res.status(500).json({ message: "Seat load error" });
      res.json({ seats: results });
    });
  });
});

app.post("/admin/seats", verifyToken, allowRoles("admin"), (req, res) => {
  const { seat_id, type, x, y } = req.body;

  if (!seat_id || !type || x === undefined || y === undefined) {
    return res.status(400).json({ message: "Missing seat data" });
  }

  db.query(
    "INSERT INTO seats (seat_id, type, x, y, status) VALUES (?, ?, ?, ?, ?)",
    [seat_id, type, x, y, "available"],
    (err) => {
      if (err) return res.status(400).json({ message: "Seat add error" });
      res.json({ message: "Seat added" });
    }
  );
});

app.put("/admin/seats/:id", verifyToken, allowRoles("admin"), (req, res) => {
  const { seat_id, type, x, y, status } = req.body;

  if (!seat_id || !type || x === undefined || y === undefined || !status) {
    return res.status(400).json({ message: "Missing seat data" });
  }

  db.query(
    "UPDATE seats SET seat_id=?, type=?, x=?, y=?, status=? WHERE id=?",
    [seat_id, type, x, y, status, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ message: "Seat update error" });
      res.json({ message: "Seat updated" });
    }
  );
});

app.delete("/admin/seats/:id", verifyToken, allowRoles("admin"), (req, res) => {
  db.query("DELETE FROM seats WHERE id=?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: "Seat delete error" });
    res.json({ message: "Seat deleted" });
  });
});

app.get("/available-seats", verifyToken, (req, res) => {
  const { booking_date, start_time, end_time } = req.query;

  if (!booking_date || !start_time || !end_time) {
    return res.status(400).json({ message: "Missing time data" });
  }

  expireLateBookings((expireErr) => {
    if (expireErr) return res.status(500).json({ message: "Auto cancel error" });

    db.query(
      `
      SELECT seats.*,
        CASE
          WHEN bookings.id IS NULL THEN 'available'
          ELSE 'booked'
        END AS current_status
      FROM seats
      LEFT JOIN bookings
        ON seats.seat_id = bookings.seat_id
        AND bookings.booking_date = ?
        AND NOT (bookings.end_time <= ? OR bookings.start_time >= ?)
      ORDER BY seats.seat_id
      `,
      [booking_date, start_time, end_time],
      (err, results) => {
        if (err) return res.status(500).json({ message: "Seat availability error" });
        res.json({ seats: results });
      }
    );
  });
});

app.get("/seat-bookings", verifyToken, (req, res) => {
  const { seat_id, booking_date } = req.query;

  if (!seat_id || !booking_date) {
    return res.status(400).json({ message: "Missing seat/date data" });
  }

  expireLateBookings((expireErr) => {
    if (expireErr) return res.status(500).json({ message: "Auto cancel error" });

    db.query(
      `
      SELECT id, seat_id, booking_date, start_time, end_time
      FROM bookings
      WHERE seat_id = ?
      AND booking_date = ?
      ORDER BY start_time
      `,
      [seat_id, booking_date],
      (err, seatBookings) => {
        if (err) return res.status(500).json({ message: "Seat bookings load error" });

        db.query(
          `
          SELECT COALESCE(SUM(TIME_TO_SEC(TIMEDIFF(end_time, start_time)) / 60), 0) AS used_minutes
          FROM bookings
          WHERE user_id = ?
          AND booking_date = ?
          `,
          [req.user.id, booking_date],
          (err, usedRows) => {
            if (err) return res.status(500).json({ message: "User daily time load error" });

            const usedMinutes = Number(usedRows[0].used_minutes || 0);

            res.json({
              bookings: seatBookings,
              used_minutes: usedMinutes,
              remaining_minutes: Math.max(0, 240 - usedMinutes)
            });
          }
        );
      }
    );
  });
});

app.post("/book-seat", verifyToken, (req, res) => {
  const { seat_id, activity, booking_date, start_time, end_time } = req.body;

  if (!seat_id || !activity || !booking_date || !start_time || !end_time) {
    return res.status(400).json({ message: "Missing booking data" });
  }

  if (!isWithinNext24Hours(booking_date, start_time)) {
    return res.status(400).json({ message: "You can only book within the next 24 hours" });
  }

  const userId = req.user.id;
  const durationMinutes = timeToMinutes(end_time) - timeToMinutes(start_time);

  if (durationMinutes <= 0) {
    return res.status(400).json({ message: "End time must be after start time" });
  }

  if (durationMinutes > 240) {
    return res.status(400).json({ message: "Limit time is 4 hours per day" });
  }

  expireLateBookings((expireErr) => {
    if (expireErr) return res.status(500).json({ message: "Auto cancel error" });

    db.query(
      `
      SELECT COALESCE(SUM(TIME_TO_SEC(TIMEDIFF(end_time, start_time)) / 60), 0) AS used_minutes
      FROM bookings
      WHERE user_id = ?
      AND booking_date = ?
      `,
      [userId, booking_date],
      (err, usedRows) => {
        if (err) return res.status(500).json({ message: "Booking check error" });

        const usedMinutes = Number(usedRows[0].used_minutes || 0);

        if (usedMinutes + durationMinutes > 240) {
          return res.status(400).json({ message: "You can only book 4 hours per day" });
        }

        db.query(
          `
          SELECT *
          FROM bookings
          WHERE seat_id = ?
          AND booking_date = ?
          AND NOT (end_time <= ? OR start_time >= ?)
          `,
          [seat_id, booking_date, start_time, end_time],
          (err, seatBookings) => {
            if (err) return res.status(500).json({ message: "Seat check error" });

            if (seatBookings.length > 0) {
              return res.status(400).json({
                message: "This seat is already booked during this time"
              });
            }

            db.query(
              `
              INSERT INTO bookings
              (user_id, seat_id, activity, booking_date, start_time, end_time, duration_hours)
              VALUES (?, ?, ?, ?, ?, ?, ?)
              `,
              [
                userId,
                seat_id,
                activity,
                booking_date,
                start_time,
                end_time,
                durationMinutes / 60
              ],
              (err) => {
                if (err) return res.status(500).json({ message: "Booking error" });
                res.json({ message: "Booking success" });
              }
            );
          }
        );
      }
    );
  });
});

app.get("/history", verifyToken, (req, res) => {
  expireLateBookings((expireErr) => {
    if (expireErr) return res.status(500).json({ message: "Auto cancel error" });

    db.query(
      `
      SELECT id, seat_id, activity, booking_date, start_time, end_time, duration_hours, checked_in, created_at
      FROM bookings
      WHERE user_id = ?
      ORDER BY booking_date DESC, start_time DESC
      `,
      [req.user.id],
      (err, results) => {
        if (err) return res.status(500).json({ message: "History load error" });
        res.json({ history: results });
      }
    );
  });
});

app.delete("/bookings/:id/cancel", verifyToken, (req, res) => {
  db.query(
    `
    SELECT *
    FROM bookings
    WHERE id = ?
    AND user_id = ?
    `,
    [req.params.id, req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ message: "Cancel check error" });

      if (results.length === 0) {
        return res.status(404).json({ message: "Booking not found" });
      }

      const booking = results[0];
      const dateOnly = formatDateOnly(booking.booking_date);
      const startOnly = String(booking.start_time).slice(0, 5);
      const startDateTime = new Date(`${dateOnly}T${startOnly}:00+07:00`);

      if (new Date() >= startDateTime) {
        return res.status(400).json({
          message: "You can only cancel before the booking start time"
        });
      }

      db.query(
        "DELETE FROM bookings WHERE id = ? AND user_id = ?",
        [req.params.id, req.user.id],
        (err) => {
          if (err) return res.status(500).json({ message: "Cancel error" });
          res.json({ message: "Booking cancelled" });
        }
      );
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
