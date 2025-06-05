// controllers/productController.js
import db from '../config/db.js';

export const createProduct = async (req, res) => {
  try {
    const product = req.body;
    const [result] = await db.query('INSERT INTO products SET ?', [product]);
    res.status(201).json({ success: true, product_id: result.insertId });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const getAllProducts = async (req, res) => {
  try {
    const [products] = await db.query('SELECT * FROM products');
    res.json({ success: true, products });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const getProductById = async (req, res) => {
  try {
    const [product] = await db.query('SELECT * FROM products WHERE product_id = ?', [req.params.id]);
    if (product.length === 0) return res.status(404).json({ success: false, message: 'Product not found' });
    res.json({ success: true, product: product[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const updateProduct = async (req, res) => {
  try {
    const updates = req.body;
    await db.query('UPDATE products SET ? WHERE product_id = ?', [updates, req.params.id]);
    res.json({ success: true, message: 'Product updated' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const deleteProduct = async (req, res) => {
  try {
    await db.query('DELETE FROM products WHERE product_id = ?', [req.params.id]);
    res.json({ success: true, message: 'Product deleted' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};


