require('dotenv').config();

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const { normalizeName, hashNationalId, decryptPassword, validNationalId } = require('./src/security');

const app = express();
const port = Number(process.env.PORT || 3000);

if (!process.env.DATABASE_URL || !process.env.NATIONAL_ID_HMAC_KEY || !process.env.PASSWORD_ENCRYPTION_KEY) {
  console.error('Missing required environment variables. Configure DATABASE_URL, NATIONAL_ID_HMAC_KEY, and PASSWORD_ENCRYPTION_KEY.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'false' ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000
});

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: []
    }
  },
  referrerPolicy: { policy: 'no-referrer' }
}));
app.use(compression());
app.use(express.json({ limit: '8kb' }));

const lookupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'تم تجاوز عدد المحاولات المسموح بها. حاول مرة أخرى بعد قليل.' },
  skipSuccessfulRequests: false
});

app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0,
  setHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
  }
}));

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch {
    res.status(503).json({ status: 'unavailable' });
  }
});

app.post('/api/lookup', lookupLimiter, async (req, res) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
    'Expires': '0'
  });

  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const nationalId = typeof req.body?.nationalId === 'string' ? req.body.nationalId.replace(/\s/g, '') : '';

  if (!name || name.length > 180 || !validNationalId(nationalId)) {
    return res.status(400).json({ error: 'يرجى إدخال الاسم والرقم القومي المكوّن من 14 رقمًا بصورة صحيحة.' });
  }

  const normalized = normalizeName(name);
  if (normalized.length < 6) {
    return res.status(400).json({ error: 'يرجى إدخال الاسم الكامل كما هو مسجل بالمدرسة.' });
  }

  try {
    const nationalHash = hashNationalId(nationalId);
    const result = await pool.query(
      `SELECT student_name, student_code, username, password_encrypted
       FROM students
       WHERE name_normalized = $1 AND national_id_hash = $2
       LIMIT 2`,
      [normalized, nationalHash]
    );

    if (result.rowCount !== 1) {
      return res.status(404).json({ error: 'تعذر التحقق من البيانات المدخلة. راجع الاسم والرقم القومي وحاول مرة أخرى.' });
    }

    const student = result.rows[0];
    let password;
    try {
      password = decryptPassword(student.password_encrypted);
    } catch {
      console.error('Credential decryption failed for a record.');
      return res.status(500).json({ error: 'تعذر عرض البيانات حاليًا. يرجى التواصل مع مسؤول النظام.' });
    }

    return res.json({
      studentName: student.student_name,
      studentCode: String(student.student_code ?? ''),
      username: String(student.username ?? ''),
      password
    });
  } catch {
    // Never log submitted names, national IDs, or credentials.
    console.error('Student lookup failed.');
    return res.status(500).json({ error: 'حدث خطأ أثناء التحقق. حاول مرة أخرى لاحقًا.' });
  }
});

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const server = app.listen(port, () => console.log(`Student portal listening on port ${port}`));

async function shutdown() {
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
