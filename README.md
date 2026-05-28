# Booking-seat-app
setup

- Install Node.js
    node -v
    npm -v

- Install MySQL
    mysql --version


1. data base
1.1

USE library_app;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,

  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,

  email VARCHAR(100) UNIQUE NOT NULL,

  password VARCHAR(255) NOT NULL,

  student_id VARCHAR(50) UNIQUE NOT NULL,

  role ENUM('user', 'admin') DEFAULT 'user',

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

1.2
CREATE TABLE seats (
  id INT AUTO_INCREMENT PRIMARY KEY,
  seat_id VARCHAR(20) UNIQUE NOT NULL,
  type VARCHAR(50) NOT NULL,
  x INT NOT NULL,
  y INT NOT NULL,
  status ENUM('available','booked') DEFAULT 'available'
);
1.3
CREATE TABLE bookings (
  id INT AUTO_INCREMENT PRIMARY KEY,

  user_id INT NOT NULL,

  seat_id VARCHAR(50) NOT NULL,

  activity VARCHAR(50),

  booking_date DATE NOT NULL,

  start_time TIME NOT NULL,

  end_time TIME NOT NULL,

  duration_hours INT DEFAULT 4,

  checked_in BOOLEAN DEFAULT false,

  checked_in_at DATETIME NULL,

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

4.ALTER TABLE users ADD profile_image VARCHAR(255);

note:  SHOW TABLES;
       SELECT * FROM seats;
       SELECT * FROM users;
       SELECT * FROM bookings  
       DESCRIBE bookings;



update to be admin

UPDATE users
SET role = 'admin'
WHERE email = 'pang@test.com';

2. back up  run : 

-------------
cd backend
node -v
npm install
node server.js
--------------
3. font end run:  frontend/index.html 