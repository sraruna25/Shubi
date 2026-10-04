require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const twilio = require('twilio');

const {
  TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SID,
  MIDDLEWARE_API_KEY, PORT = 3000
} = process.env;

const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
const verify = client.verify.v2.services(TWILIO_VERIFY_SID);

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

// Health check, no auth
app.get('/health', (_, res) => res.send('ok'));

// API key auth
app.use((req, res, next) => {
  if (req.headers['x-api-key'] !== MIDDLEWARE_API_KEY) {
    return res.status(401).json({ status: 'unauthorized' });
  }
  next();
});

const DEFAULT_CC = process.env.DEFAULT_COUNTRY_CODE || '91';
function normalizePhone(raw) {
  let p = String(raw || '').replace(/[^\d+]/g, '');
  if (p.startsWith('00')) p = '+' + p.slice(2);
  if (!p.startsWith('+')) {
    if (p.length === 11 && p.startsWith('0')) p = '+' + DEFAULT_CC + p.slice(1);
    else if (p.length === 10) p = '+' + DEFAULT_CC + p;
    else p = '+' + p;
  }
  return /^\+[1-9]\d{6,14}$/.test(p) ? p : null;
}

// Rate limit PER PHONE NUMBER (all Landbot calls share one server IP)
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => normalizePhone(req.body && req.body.phone) || 'invalid',
  handler: (req, res) => res.status(429).json({ status: 'rate_limited' }),
  validate: false
});
app.use(limiter);

app.post('/send-otp', async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  if (!phone) return res.status(400).json({ status: 'invalid_phone' });
  try {
    const v = await verify.verifications.create({ to: phone, channel: 'sms' });
    return res.json({ status: v.status });
  } catch (err) {
    console.error('send-otp error:', err.code, err.message);
    if (err.status === 429 || err.code === 20429) return res.status(429).json({ status: 'rate_limited' });
    return res.status(500).json({ status: 'send_failed' });
  }
});

app.post('/check-otp', async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const code = String(req.body.code || '').trim();
  if (!phone || !/^\d{4,10}$/.test(code)) {
    return res.status(400).json({ status: 'invalid_input' });
  }
  try {
    const c = await verify.verificationChecks.create({ to: phone, code });
    return res.status(c.status === 'approved' ? 200 : 422).json({ status: c.status });
  } catch (err) {
    if (err.status === 404) return res.status(410).json({ status: 'expired' });
    console.error('check-otp error:', err.code, err.message);
    return res.status(500).json({ status: 'check_failed' });
  }
});

app.listen(PORT, () => console.log('Listening on ' + PORT));
