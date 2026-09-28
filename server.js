import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT || 3000);
const APP_LOGIN_USER = process.env.APP_LOGIN_USER || '';
const APP_LOGIN_PASSWORD = process.env.APP_LOGIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const NESTLAB_BILLING_STATUS_URL = (process.env.NESTLAB_BILLING_STATUS_URL || '').replace(/\/$/, '');
const NESTLAB_BILLING_API_KEY = process.env.NESTLAB_BILLING_API_KEY || '';
const NESTLAB_NOTIFY_SECRET = process.env.NESTLAB_NOTIFY_SECRET || '';

const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false }));

const notices = [];
const sessions = new Map();

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(part => {
    const [rawKey, ...rest] = part.trim().split('=');
    if (!rawKey) return;
    out[rawKey] = decodeURIComponent(rest.join('=') || '');
  });
  return out;
}

function signSessionId(sessionId) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
}

function createSession(username) {
  const sessionId = crypto.randomBytes(24).toString('hex');
  const token = `${sessionId}.${signSessionId(sessionId)}`;
  sessions.set(sessionId, {
    username,
    createdAt: Date.now(),
  });
  return token;
}

function getSession(req) {
  const cookies = parseCookies(req);
  const raw = cookies.sid;
  if (!raw) return null;
  const [sessionId, sig] = raw.split('.');
  if (!sessionId || !sig) return null;
  if (signSessionId(sessionId) !== sig) return null;
  const session = sessions.get(sessionId);
  if (!session) return null;
  return { sessionId, ...session };
}

function useSecureCookie() {
  return process.env.COOKIE_SECURE === 'true';
}

function setSessionCookie(res, token) {
  const secure = useSecureCookie() ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `sid=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${secure}`
  );
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'sid=; Path=/; HttpOnly; Max-Age=0');
}

function requireAuth(req, res, next) {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: 'Não autenticado' });
  }
  req.session = session;
  return next();
}

function isAuthorizedNotify(req) {
  if (!NESTLAB_NOTIFY_SECRET) return true;
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  return token === NESTLAB_NOTIFY_SECRET;
}

function credentialsMatch(username, password) {
  if (!APP_LOGIN_USER || !APP_LOGIN_PASSWORD) return false;
  const userOk = username.length === APP_LOGIN_USER.length
    && crypto.timingSafeEqual(Buffer.from(username), Buffer.from(APP_LOGIN_USER));
  const passOk = password.length === APP_LOGIN_PASSWORD.length
    && crypto.timingSafeEqual(Buffer.from(password), Buffer.from(APP_LOGIN_PASSWORD));
  return userOk && passOk;
}

async function fetchNestlabBilling() {
  if (!NESTLAB_BILLING_STATUS_URL || !NESTLAB_BILLING_API_KEY) {
    return {
      error: 'Configure NESTLAB_BILLING_STATUS_URL e NESTLAB_BILLING_API_KEY.',
      status: 503,
    };
  }

  try {
    const upstream = await fetch(NESTLAB_BILLING_STATUS_URL, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${NESTLAB_BILLING_API_KEY}`,
      },
      signal: AbortSignal.timeout(12000),
    });
    const data = await upstream.json().catch(() => ({}));
    if (!upstream.ok) {
      let message = data.error || 'Falha ao consultar NestLab';
      if (upstream.status === 401) {
        message =
          'NestLab rejeitou a NESTLAB_BILLING_API_KEY. Em /master/clientes, gere uma nova chave para o cliente CLIENT correto e cole no Coolify (sem espaços). A chave precisa ser do mesmo ambiente (nestlab.com.br).';
      }
      return { error: message, status: upstream.status, details: data, nestlabStatus: upstream.status };
    }
    return { billing: data, status: 200 };
  } catch {
    return { error: 'Não foi possível contactar a NestLab.', status: 502 };
  }
}

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    loginConfigured: Boolean(APP_LOGIN_USER && APP_LOGIN_PASSWORD),
    nestlabConfigured: Boolean(NESTLAB_BILLING_STATUS_URL && NESTLAB_BILLING_API_KEY),
    notifySecretConfigured: Boolean(NESTLAB_NOTIFY_SECRET),
  });
});

app.post('/api/billing/notice', (req, res) => {
  if (!isAuthorizedNotify(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const entry = {
    receivedAt: new Date().toISOString(),
    body: req.body,
  };
  notices.unshift(entry);
  if (notices.length > 50) notices.pop();

  console.log('[billing/notice]', JSON.stringify(entry.body));
  return res.json({ received: true });
});

app.get('/api/billing/notices', requireAuth, (_req, res) => {
  res.json({ notices });
});

app.post('/api/login', async (req, res) => {
  if (!APP_LOGIN_USER || !APP_LOGIN_PASSWORD) {
    return res.status(503).json({ error: 'Configure APP_LOGIN_USER e APP_LOGIN_PASSWORD.' });
  }

  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');

  if (!credentialsMatch(username, password)) {
    return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  }

  const billingResult = await fetchNestlabBilling();
  if (billingResult.error) {
    return res.status(billingResult.status).json({
      error: billingResult.error,
      details: billingResult.details,
      nestlabStatus: billingResult.nestlabStatus,
    });
  }

  const token = createSession(username);
  setSessionCookie(res, token);

  return res.json({
    user: { username },
    loggedInAt: new Date().toISOString(),
    billing: billingResult.billing,
  });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const billingResult = await fetchNestlabBilling();
  if (billingResult.error) {
    return res.status(502).json({
      error: billingResult.error,
      user: { username: req.session.username },
      details: billingResult.details,
      billingUnavailable: true,
    });
  }

  return res.json({
    user: { username: req.session.username },
    billing: billingResult.billing,
  });
});

app.post('/api/logout', (req, res) => {
  const session = getSession(req);
  if (session?.sessionId) sessions.delete(session.sessionId);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.get('/', (req, res) => {
  if (getSession(req)) {
    return res.redirect('/dashboard.html');
  }
  return res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`billing-client-demo listening on :${PORT}`);
});
