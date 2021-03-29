const http = require('http');
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const mysql = require('mysql2/promise');

require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

app.use(cors());
app.use(bodyParser.json());

app.post('/register', async function (req, res) {
  try {
    let user;
    // Hashes the password and inserts the info into the `user` table
    await bcrypt.hash(req.body.password, 10).then(async (hash) => {
      try {
        [user] = await req.db.query(
          `
          INSERT INTO user (email, first_name, last_name, password)
          VALUES (:email, :fname, :lname, :password);
        `,
          {
            email: req.body.email,
            fname: req.body.fName,
            lname: req.body.lName,
            password: hash,
          }
        );

        console.log('user', user);
      } catch (error) {
        return res.json('Error creating user');
        console.log('error', error);
      }
    });

    const encodedUser = jwt.sign(
      {
        userId: user.insertId,
        ...req.body,
      },
      process.env.JWT_KEY
    );

    res.json({
      data: encodedUser,
      error: false,
      msg: 'Account created',
    });
  } catch (err) {
    return res.json({
      data: null,
      error: true,
      msg: 'Error, please try again',
    });
    console.log('err', err);
  }
});

app.post('/log-in', async function (req, res) {
  try {
    const [[user]] = await req.db.query(
      `
      SELECT * FROM user WHERE email = :email
    `,
      {
        email: req.body.email,
      }
    );

    if (!user) {
      return res.json({
        data: null,
        error: true,
        msg: 'Email not found',
      });
      return;
    }

    const userPassword = `${user.password}`;

    const compare = await bcrypt.compare(req.body.password, userPassword);

    if (compare) {
      const payload = {
        userId: user.id,
        email: user.email,
        fname: user.fname,
        lname: user.lname,
        role: 4,
      };

      const encodedUser = jwt.sign(payload, process.env.JWT_KEY);

      return res.json({
        data: encodedUser,
        error: false,
        msg: '',
      });
    } else {
      return res.json({
        data: null,
        error: true,
        msg: 'Password not found',
      });
    }
  } catch (err) {
    return res.json({
      data: null,
      error: true,
      msg: 'Error logging in',
    });
    console.log('Error in /log-in', err);
  }
});

// Jwt verification checks to see if there is an authorization header with a valid jwt in it.
app.use(async function verifyJwt(req, res, next) {
  try {
    if (!req.headers.authorization) {
      throw (401, 'Invalid authorization');
    }

    const [scheme, token] = req.headers.authorization.split(' ');

    if (scheme !== 'Bearer') {
      throw (401, 'Invalid authorization');
    }

    const payload = jwt.verify(token, process.env.JWT_KEY);

    req.user = payload;
  } catch (err) {
    if (
      err.message &&
      (err.message.toUpperCase() === 'INVALID TOKEN' ||
        err.message.toUpperCase() === 'JWT EXPIRED')
    ) {
      req.status = err.status || 500;
      req.body = err.message;
      req.app.emit('jwt-error', err, req);
    } else {
      console.log();
      throw (err.status || 500, err.message);
    }
  }

  await next();
});

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept, Authorization'
  );
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, PATCH, PUT, DELETE, OPTIONS'
  );
  next();
});

app.use(async function mysqlConnection(req, res, next) {
  try {
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;

    // Traditional mode ensures not null is respected for unsupplied fields, ensures valid JavaScript dates, etc.
    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    await next();

    req.db.release();
  } catch (err) {
    // If anything downstream throw an error, we must release the connection allocated for the request
    console.log(err);
    if (req.db) req.db.release();
    throw err;
  }
});
// Get request to get all heroes, need to configure once credentials are done
app.get('/heroes', async function (req, res) {
  try {
    const [heroes] = await req.db.query(`SELECT * FROM HEROES`);
    return res.json({
      data: heroes,
      error: false,
      msg: 'Fetched Heroes Successful',
    });
  } catch (err) {
    console.log('Error in /Heroes', err);
    res.json({
      data: null,
      error: true,
      msg: 'Error fetching heroes',
    });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`listening at localhost:${port}`));
