const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_CODE = '20538090';
const DATA_FILE = path.join(__dirname, 'data.json');

app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));
// نسخة الهاتف: يقرأ index.html من الجذر مباشرة
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ---------- Storage (simple JSON file persistence, survives restarts) ----------
function defaultData() {
  return {
    teams: [
      { id: 'red',    name: 'الفريق الأحمر',  color: '#ef4444', capacity: 3, score: 0 },
      { id: 'blue',   name: 'الفريق الأزرق',  color: '#3b82f6', capacity: 3, score: 0 },
      { id: 'yellow', name: 'الفريق الأصفر',  color: '#eab308', capacity: 3, score: 0 },
      { id: 'green',  name: 'الفريق الأخضر',  color: '#22c55e', capacity: 3, score: 0 }
    ],
    users: {},   // username -> { id, passHash, avatar, teamId }
    sessions: {} // token -> username
  };
}

function loadData() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    const d = defaultData();
    saveData(d);
    return d;
  }
}
function saveData(d) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(d));
}
let db = loadData();

// ---------- helpers ----------
function hash(pass) {
  return crypto.createHash('sha256').update('team-salt::' + pass).digest('hex');
}
function newToken() {
  return crypto.randomBytes(24).toString('hex');
}
function userFromToken(req) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  if (!token || !db.sessions[token]) return null;
  const username = db.sessions[token];
  return { username, user: db.users[username], token };
}
function publicState() {
  const teams = db.teams.map(t => ({
    id: t.id, name: t.name, color: t.color, capacity: t.capacity, score: t.score,
    members: Object.entries(db.users)
      .filter(([u, v]) => v.teamId === t.id)
      .map(([u, v]) => ({ username: u, avatar: v.avatar || null }))
  }));
  return { teams, totalUsers: Object.keys(db.users).length };
}

// ---------- auth ----------
app.post('/api/signup', (req, res) => {
  const { username, password, avatar } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
  const uname = String(username).trim();
  if (uname.length < 2) return res.status(400).json({ error: 'اسم المستخدم قصير جداً' });
  if (String(password).length < 4) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 4 أحرف على الأقل' });
  if (db.users[uname]) return res.status(400).json({ error: 'اسم المستخدم موجود مسبقاً، اختر اسماً آخر' });
  db.users[uname] = { id: crypto.randomBytes(8).toString('hex'), passHash: hash(password), avatar: avatar || null, teamId: null };
  const token = newToken();
  db.sessions[token] = uname;
  saveData(db);
  res.json({ ok: true, token, username: uname });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const uname = String(username || '').trim();
  const u = db.users[uname];
  if (!u || u.passHash !== hash(password || '')) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  const token = newToken();
  db.sessions[token] = uname;
  saveData(db);
  res.json({ ok: true, token, username: uname });
});

app.post('/api/admin-login', (req, res) => {
  const { code } = req.body || {};
  if (String(code) !== ADMIN_CODE) return res.status(401).json({ error: 'الرمز غير صحيح' });
  const token = newToken();
  db.sessions[token] = '__ADMIN__';
  saveData(db);
  res.json({ ok: true, token, admin: true });
});

// ---------- state ----------
app.get('/api/state', (req, res) => {
  const me = userFromToken(req);
  res.json({
    ...publicState(),
    me: me && me.user ? { username: me.username, avatar: me.user.avatar, teamId: me.user.teamId } : null,
    admin: !!(me && me.user === undefined && me.username === '__ADMIN__') || !!(me && me.username === '__ADMIN__')
  });
});

// ---------- team selection (server-enforced capacity) ----------
app.post('/api/pick-team', (req, res) => {
  const me = userFromToken(req);
  if (!me || !me.user || me.user === '__ADMIN__' || me.username === '__ADMIN__') return res.status(401).json({ error: 'سجّل الدخول أولاً' });
  if (me.user.teamId) return res.status(400).json({ error: 'لقد اخترت فريقك بالفعل' });
  const { teamId } = req.body || {};
  const team = db.teams.find(t => t.id === teamId);
  if (!team) return res.status(400).json({ error: 'الفريق غير موجود' });
  const count = Object.values(db.users).filter(u => u.teamId === team.id).length;
  if (count >= team.capacity) return res.status(400).json({ error: 'هذا الفريق مكتمل (' + team.capacity + '/' + team.capacity + ')، اختر فريقاً آخر' });
  me.user.teamId = team.id;
  saveData(db);
  res.json({ ok: true });
});

// ---------- admin actions ----------
function requireAdmin(req, res) {
  const me = userFromToken(req);
  if (!me || me.username !== '__ADMIN__') { res.status(401).json({ error: 'صلاحية الأدمن مطلوبة' }); return null; }
  return me;
}

app.post('/api/admin/kick', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { username } = req.body || {};
  if (!db.users[username]) return res.status(400).json({ error: 'العضو غير موجود' });
  db.users[username].teamId = null;
  saveData(db);
  res.json({ ok: true });
});

app.post('/api/admin/score', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { teamId, score } = req.body || {};
  const team = db.teams.find(t => t.id === teamId);
  if (!team) return res.status(400).json({ error: 'الفريق غير موجود' });
  team.score = Number(score) || 0;
  saveData(db);
  res.json({ ok: true });
});

app.post('/api/admin/capacity', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { teamId, capacity } = req.body || {};
  const team = db.teams.find(t => t.id === teamId);
  if (!team) return res.status(400).json({ error: 'الفريق غير موجود' });
  team.capacity = Math.max(1, Number(capacity) || 3);
  saveData(db);
  res.json({ ok: true });
});

app.post('/api/admin/add-team', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { name, color, capacity } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'اسم الفريق مطلوب' });
  const id = 'team_' + crypto.randomBytes(4).toString('hex');
  db.teams.push({ id, name: String(name).trim(), color: color || '#a855f7', capacity: Math.max(1, Number(capacity) || 3), score: 0 });
  saveData(db);
  res.json({ ok: true, id });
});

app.post('/api/admin/delete-team', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const { teamId } = req.body || {};
  db.teams = db.teams.filter(t => t.id !== teamId);
  Object.values(db.users).forEach(u => { if (u.teamId === teamId) u.teamId = null; });
  saveData(db);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log('Server running on port ' + PORT));
