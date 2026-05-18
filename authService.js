const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const db     = require('./database');

const JWT_SECRET  = process.env.JWT_SECRET  || 'soap-auth-secret-key-change-in-production';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '24h';

// ── RegisterUser ─────────────────────────────────────────────────
function registerUser(args, callback) {
  const { username, password, email } = args;

  if (!username || !password || !email) {
    return callback(null, { success: false, message: 'Бүх талбарыг бөглөнө үү' });
  }

  const hash = bcrypt.hashSync(password, 10);

  db.run(
    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
    [username.trim(), email.trim(), hash],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return callback(null, { success: false, message: 'Нэвтрэх нэр эсвэл имэйл аль хэдийн бүртгэлтэй' });
        }
        return callback(null, { success: false, message: 'Бүртгэл үүсгэхэд алдаа гарлаа' });
      }
      callback(null, { success: true, message: 'Бүртгэл амжилттай үүсгэгдлээ', userId: this.lastID });
    }
  );
}

// ── LoginUser ────────────────────────────────────────────────────
function loginUser(args, callback) {
  const { username, password } = args;

  if (!username || !password) {
    return callback(null, { success: false, message: 'Нэвтрэх нэр болон нууц үгийг оруулна уу', token: '', userId: 0 });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username.trim()], (err, user) => {
    if (err || !user) {
      return callback(null, { success: false, message: 'Нэвтрэх нэр эсвэл нууц үг буруу', token: '', userId: 0 });
    }

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) {
      return callback(null, { success: false, message: 'Нэвтрэх нэр эсвэл нууц үг буруу', token: '', userId: 0 });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    // Store token in DB
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    db.run(
      'INSERT OR REPLACE INTO tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
      [token, user.id, expiresAt],
      (dbErr) => {
        if (dbErr) console.error('Token хадгалахад алдаа:', dbErr.message);
      }
    );

    callback(null, { success: true, message: 'Нэвтрэлт амжилттай', token, userId: user.id });
  });
}

// ── ValidateToken ────────────────────────────────────────────────
function validateToken(args, callback) {
  const { token } = args;

  if (!token) {
    return callback(null, { valid: false, userId: 0, username: '', role: '' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Check token exists in DB (not revoked)
    db.get(
      'SELECT * FROM tokens WHERE token = ? AND expires_at > datetime("now")',
      [token],
      (err, row) => {
        if (err || !row) {
          return callback(null, { valid: false, userId: 0, username: '', role: '' });
        }
        callback(null, {
          valid:    true,
          userId:   decoded.userId,
          username: decoded.username,
          role:     decoded.role || 'user'
        });
      }
    );
  } catch (err) {
    callback(null, { valid: false, userId: 0, username: '', role: '' });
  }
}

module.exports = { registerUser, loginUser, validateToken };
