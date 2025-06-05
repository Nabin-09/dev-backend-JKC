// config/db.js
import mysql from 'mysql2';
import dotenv from 'dotenv';

dotenv.config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'crm_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Wrap with promise to enable async/await
const db = pool.promise();

export default db;
