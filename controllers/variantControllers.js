import db from '../config/db.js';

export const createVariant = async (req, res) => {
  try {
    const { productId } = req.params;
    const variant = { ...req.body, product_id: productId };
    const [result] = await db.query('INSERT INTO product_variants SET ?', [variant]);
    res.status(201).json({ success: true, variant_id: result.insertId });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const getVariantsForProduct = async (req, res) => {
  try {
    const [variants] = await db.query('SELECT * FROM product_variants WHERE product_id = ?', [req.params.productId]);
    res.json({ success: true, variants });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const getVariantById = async (req, res) => {
  try {
    const [variant] = await db.query('SELECT * FROM product_variants WHERE variant_id = ?', [req.params.id]);
    if (variant.length === 0) return res.status(404).json({ success: false, message: 'Variant not found' });
    res.json({ success: true, variant: variant[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const updateVariant = async (req, res) => {
  try {
    const updates = req.body;
    await db.query('UPDATE product_variants SET ? WHERE variant_id = ?', [updates, req.params.id]);
    res.json({ success: true, message: 'Variant updated' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

export const deleteVariant = async (req, res) => {
  try {
    await db.query('DELETE FROM product_variants WHERE variant_id = ?', [req.params.id]);
    res.json({ success: true, message: 'Variant deleted' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
