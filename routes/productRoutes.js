// routes/productRoutes.js
import express from 'express';
import {
  createProduct,
  getAllProducts,
  getProductById,
  updateProduct,
  deleteProduct
} from '../controllers/productControllers.js';
import {
  createVariant,
  getVariantsForProduct,
  getVariantById,
  updateVariant,
  deleteVariant
} from '../controllers/variantControllers.js';

const router = express.Router();

// Product routes
router.post('/products', createProduct);
router.get('/products', getAllProducts);
router.get('/products/:id', getProductById);
router.put('/products/:id', updateProduct);
router.delete('/products/:id', deleteProduct);

// Variant routes
router.post('/products/:productId/variants', createVariant);
router.get('/products/:productId/variants', getVariantsForProduct);
router.get('/variants/:id', getVariantById);
router.put('/variants/:id', updateVariant);
router.delete('/variants/:id', deleteVariant);

export default router;
