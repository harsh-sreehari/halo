import express, { Request, Response } from 'express';

const app = express();
app.use(express.json());

// In-memory test state
interface Invoice {
  id: string;
  title: string;
  amount: number;
  userId: string;
}

interface Order {
  id: string;
  status: string;
  paid: boolean;
  total: number;
  userId: string;
}

interface Coupon {
  code: string;
  discount: number;
  used: boolean;
  redeemCount: number;
}

const invoices: Record<string, Invoice> = {
  'inv-b-1': { id: 'inv-b-1', title: 'Confidential Invoice B', amount: 450.0, userId: 'halo_user_b' },
};

const orders: Record<string, Order> = {
  '1': { id: '1', status: 'created', paid: false, total: 100.0, userId: 'halo_user_a' },
};

const coupons: Record<string, Coupon> = {
  'DISCOUNT50': { code: 'DISCOUNT50', discount: 50.0, used: false, redeemCount: 0 },
};

// ----------------------------------------------------------------------------
// Benign Safe Routes (for False-Positive Validation)
// ----------------------------------------------------------------------------

export async function getHealth(req: Request, res: Response) {
  return res.status(200).json({ status: 'ok' });
}

export async function getPublicInfo(req: Request, res: Response) {
  return res.status(200).json({
    version: '1.0.0',
    name: 'halo-testbed-api',
    status: 'operational',
  });
}

// ----------------------------------------------------------------------------
// 1. BOLA Read Flaw: Fetches invoice by ID without verifying req.user.id === invoice.userId
// ----------------------------------------------------------------------------
export async function getInvoice(req: Request, res: Response) {
  const { id } = req.params;
  const invoice = invoices[id];
  if (!invoice) {
    return res.status(404).json({ error: 'Invoice not found' });
  }
  // VULNERABILITY: No ownership check (req.user.id === invoice.userId)
  return res.status(200).json(invoice);
}

// ----------------------------------------------------------------------------
// 2. BOLA Write Flaw: Updates invoice by ID without verifying ownership
// ----------------------------------------------------------------------------
export async function updateInvoice(req: Request, res: Response) {
  const { id } = req.params;
  const invoice = invoices[id];
  if (!invoice) {
    return res.status(404).json({ error: 'Invoice not found' });
  }
  // VULNERABILITY: Updates resource directly without authorization boundary check
  Object.assign(invoice, req.body);
  return res.status(200).json({ ...invoice, updated: true });
}

// ----------------------------------------------------------------------------
// 3. BFLA Flaw: Administrative endpoint lacking role/privilege verification
// ----------------------------------------------------------------------------
export async function getAdminSettings(req: Request, res: Response) {
  // VULNERABILITY: No admin role verification check
  return res.status(200).json({
    settings: {
      maintenanceMode: false,
      debug: true,
      maxLoginAttempts: 5,
      encryptionAlgorithm: 'AES-256-GCM',
    },
  });
}

// ----------------------------------------------------------------------------
// 4. Workflow Bypass: Transitions order to shipped without verifying payment status
// ----------------------------------------------------------------------------
export async function shipOrder(req: Request, res: Response) {
  const { id } = req.params;
  const order = orders[id] || { id, status: 'created', paid: false, total: 100.0, userId: 'halo_user_a' };
  orders[id] = order;

  // VULNERABILITY: Skips invariant check (order.paid === true)
  order.status = 'shipped';
  return res.status(200).json({
    id: order.id,
    status: 'shipped',
    paid: order.paid,
    message: 'Order shipped successfully without requiring prior payment',
  });
}

// ----------------------------------------------------------------------------
// 5. Mass Assignment / Price Tampering: Accepts untrusted total from client
// ----------------------------------------------------------------------------
export async function checkoutCart(req: Request, res: Response) {
  const { items, total } = req.body;
  // VULNERABILITY: Binds client-provided total directly without server-side recalculation
  const finalTotal = typeof total !== 'undefined' ? total : 100.0;
  return res.status(200).json({
    orderId: 'ord_checkout_1',
    items: items || [],
    total: finalTotal,
    status: 'confirmed',
  });
}

// ----------------------------------------------------------------------------
// 6. Concurrency Race: Non-atomic coupon redemption allows duplicate redemption
// ----------------------------------------------------------------------------
export async function applyCoupon(req: Request, res: Response) {
  const code = req.body?.code || req.body?.coupon || 'DISCOUNT50';
  const coupon = coupons[code];

  if (!coupon) {
    return res.status(404).json({ error: 'Invalid coupon' });
  }

  // VULNERABILITY: Non-atomic TOCTOU check-then-act with concurrency race window
  if (coupon.used) {
    return res.status(400).json({ error: 'Coupon already redeemed' });
  }

  // Intentional race window
  await new Promise((resolve) => setTimeout(resolve, 50));

  coupon.used = true;
  coupon.redeemCount += 1;

  return res.status(200).json({
    code: coupon.code,
    discount: coupon.discount,
    redeemed: true,
    count: coupon.redeemCount,
  });
}

// Helper registration & login endpoints
export async function registerUser(req: Request, res: Response) {
  const { username, email } = req.body;
  const token = username === 'halo_user_b' ? 'halo_token_user_b' : 'halo_token_user_a';
  return res.status(201).json({ token, username, email });
}

export async function loginUser(req: Request, res: Response) {
  const { username } = req.body;
  const token = username === 'halo_admin' ? 'halo_token_admin' : 'halo_token_user_a';
  return res.status(200).json({ token });
}

export async function createInvoice(req: Request, res: Response) {
  const id = `inv-${Date.now()}`;
  invoices[id] = { id, title: req.body?.name || 'Invoice', amount: req.body?.amount || 100, userId: 'halo_user_b' };
  return res.status(201).json(invoices[id]);
}

// Route Mappings
app.get('/health', getHealth);
app.get('/api/v1/public/info', getPublicInfo);
app.get('/api/v1/invoices/:id', getInvoice);
app.put('/api/v1/invoices/:id', updateInvoice);
app.get('/api/v1/admin/settings', getAdminSettings);
app.post('/api/v1/orders/:id/ship', shipOrder);
app.post('/api/v1/cart/checkout', checkoutCart);
app.post('/api/v1/coupons/apply', applyCoupon);

export default app;

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`Halo Testbed listening on port ${port}`);
  });
}
