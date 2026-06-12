/**
 * OLDOON — Study Loud
 * Full Production Backend
 * Node.js + Express + Socket.IO + LowDB (JSON)
 */

require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const rateLimit = require('express-rate-limit');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const fs = require('fs');

// ─── DB SETUP ────────────────────────────────────────────────
const dbDir = path.join(__dirname, 'data');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const adapter = new FileSync(path.join(dbDir, 'db.json'));
const db = low(adapter);

db.defaults({
  users: [],
  profiles: [],
  messages: [],        // DMs
  room_messages: [],   // Vibe room chat
  connections: [],     // buddy connections (pending / accepted)
  rooms: [],           // vibe rooms
  quiz_results: [],
  progress: [],        // syllabus progress per user
  notifications: [],
}).write();

// ─── CONFIG ──────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'oldoon-secret-2026-change-in-prod';
const PORT = process.env.PORT || 3000;

const app = express();
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

// ─── MIDDLEWARE ───────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'client/public')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use('/api/', limiter);

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────
function authRequired(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── HELPERS ─────────────────────────────────────────────────
function safeUser(u) {
  const { password, ...safe } = u;
  return safe;
}

function now() { return new Date().toISOString(); }

// ─── DEFAULT ROOMS ───────────────────────────────────────────
const defaultRooms = [
  { id: 'room-dsa',       name: 'Data Structures grind',    desc: 'Solving DSA problems together, mics on for doubts.',  tag: 'B.Tech CSE',  maxPeople: 20 },
  { id: 'room-neet',      name: 'NEET Biology revision',    desc: 'NCERT line-by-line revision, quiet focus room.',       tag: 'NEET',         maxPeople: 30 },
  { id: 'room-upsc',      name: 'UPSC Current Affairs',     desc: 'Daily newspaper discussion + notes sharing.',         tag: 'UPSC',         maxPeople: 25 },
  { id: 'room-chem12',    name: 'Class 12 Boards — Chemistry', desc: 'Numericals practice with screen share.',           tag: 'Class 12',     maxPeople: 20 },
  { id: 'room-jeephysics',name: 'JEE Physics doubt room',   desc: 'Drop your toughest numericals, group solves.',       tag: 'JEE',          maxPeople: 40 },
  { id: 'room-mba',       name: 'MBA case study circle',    desc: 'Weekly case discussions + mock GD practice.',        tag: 'MBA',          maxPeople: 15 },
];

if (db.get('rooms').value().length === 0) {
  db.get('rooms').push(...defaultRooms.map(r => ({ ...r, createdAt: now() }))).write();
}

// ─────────────────────────────────────────────────────────────
//  AUTH ROUTES
// ─────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name)
    return res.status(400).json({ error: 'Name, email and password are required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const exists = db.get('users').find({ email: email.toLowerCase() }).value();
  if (exists) return res.status(409).json({ error: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 10);
  const userId = uuidv4();
  const user = { id: userId, email: email.toLowerCase(), password: hashed, name, createdAt: now() };

  db.get('users').push(user).write();

  // Create empty profile
  db.get('profiles').push({
    userId,
    name,
    bio: '',
    avatar: '',         // base64 or URL
    level: '',
    course: '',
    year: '',
    tags: [],
    streak: 0,
    lastActive: now(),
    isOnline: false,
  }).write();

  const token = jwt.sign({ id: userId, email: user.email, name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safeUser(user) });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.get('users').find({ email: email?.toLowerCase() }).value();
  if (!user) return res.status(401).json({ error: 'No account with that email' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Wrong password' });

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safeUser(user) });
});

// GET /api/auth/me
app.get('/api/auth/me', authRequired, (req, res) => {
  const user = db.get('users').find({ id: req.user.id }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(safeUser(user));
});

// ─────────────────────────────────────────────────────────────
//  PROFILE ROUTES
// ─────────────────────────────────────────────────────────────

// GET /api/profile/:userId
app.get('/api/profile/:userId', authRequired, (req, res) => {
  const profile = db.get('profiles').find({ userId: req.params.userId }).value();
  if (!profile) return res.status(404).json({ error: 'Profile not found' });
  res.json(profile);
});

// PATCH /api/profile  (update own profile)
app.patch('/api/profile', authRequired, (req, res) => {
  const { bio, avatar, level, course, year, tags, name } = req.body;
  const update = { lastActive: now() };
  if (bio !== undefined) update.bio = bio;
  if (avatar !== undefined) update.avatar = avatar;
  if (level !== undefined) update.level = level;
  if (course !== undefined) update.course = course;
  if (year !== undefined) update.year = year;
  if (tags !== undefined) update.tags = tags;
  if (name !== undefined) {
    update.name = name;
    db.get('users').find({ id: req.user.id }).assign({ name }).write();
  }

  db.get('profiles').find({ userId: req.user.id }).assign(update).write();
  const profile = db.get('profiles').find({ userId: req.user.id }).value();
  res.json(profile);
});

// ─────────────────────────────────────────────────────────────
//  STUDY BUDDIES
// ─────────────────────────────────────────────────────────────

// GET /api/buddies  — filtered list of users (not self, with profile)
app.get('/api/buddies', authRequired, (req, res) => {
  const { level, course, search } = req.query;
  let profiles = db.get('profiles').value().filter(p => p.userId !== req.user.id);

  if (level && level !== 'all') profiles = profiles.filter(p => p.level === level);
  if (course && course !== 'all') profiles = profiles.filter(p => p.course === course);
  if (search) {
    const q = search.toLowerCase();
    profiles = profiles.filter(p =>
      p.name?.toLowerCase().includes(q) ||
      p.tags?.some(t => t.toLowerCase().includes(q)) ||
      p.bio?.toLowerCase().includes(q) ||
      p.course?.toLowerCase().includes(q)
    );
  }

  // attach connection status
  const enriched = profiles.map(p => {
    const conn = db.get('connections').find(c =>
      (c.from === req.user.id && c.to === p.userId) ||
      (c.to === req.user.id && c.from === p.userId)
    ).value();
    return { ...p, connectionStatus: conn ? conn.status : 'none', connectionId: conn?.id };
  });

  res.json(enriched);
});

// POST /api/buddies/connect  — send connection request
app.post('/api/buddies/connect', authRequired, (req, res) => {
  const { toUserId } = req.body;
  if (toUserId === req.user.id) return res.status(400).json({ error: "Can't connect with yourself" });

  const exists = db.get('connections').find(c =>
    (c.from === req.user.id && c.to === toUserId) ||
    (c.from === toUserId && c.to === req.user.id)
  ).value();
  if (exists) return res.status(409).json({ error: 'Connection already exists', connection: exists });

  const conn = { id: uuidv4(), from: req.user.id, to: toUserId, status: 'pending', createdAt: now() };
  db.get('connections').push(conn).write();

  // Notify
  db.get('notifications').push({
    id: uuidv4(), userId: toUserId, type: 'connection_request',
    fromUserId: req.user.id, fromName: req.user.name, read: false, createdAt: now()
  }).write();

  io.to(`user:${toUserId}`).emit('notification', { type: 'connection_request', fromName: req.user.name });
  res.json(conn);
});

// PATCH /api/buddies/connect/:id  — accept/reject
app.patch('/api/buddies/connect/:id', authRequired, (req, res) => {
  const { status } = req.body; // 'accepted' | 'rejected'
  const conn = db.get('connections').find({ id: req.params.id, to: req.user.id }).value();
  if (!conn) return res.status(404).json({ error: 'Request not found' });

  db.get('connections').find({ id: req.params.id }).assign({ status, updatedAt: now() }).write();
  res.json({ ...conn, status });
});

// GET /api/buddies/connections  — my accepted connections
app.get('/api/buddies/connections', authRequired, (req, res) => {
  const conns = db.get('connections')
    .filter(c => (c.from === req.user.id || c.to === req.user.id) && c.status === 'accepted')
    .value();

  const enriched = conns.map(c => {
    const otherId = c.from === req.user.id ? c.to : c.from;
    const profile = db.get('profiles').find({ userId: otherId }).value();
    return { ...c, profile };
  });
  res.json(enriched);
});

// ─────────────────────────────────────────────────────────────
//  DIRECT MESSAGES
// ─────────────────────────────────────────────────────────────

// GET /api/messages/:otherUserId
app.get('/api/messages/:otherUserId', authRequired, (req, res) => {
  const other = req.params.otherUserId;
  const msgs = db.get('messages')
    .filter(m =>
      (m.from === req.user.id && m.to === other) ||
      (m.from === other && m.to === req.user.id)
    )
    .sortBy('createdAt')
    .value();
  res.json(msgs);
});

// GET /api/messages  — all conversations (latest msg per person)
app.get('/api/messages', authRequired, (req, res) => {
  const all = db.get('messages')
    .filter(m => m.from === req.user.id || m.to === req.user.id)
    .value();

  const conversations = {};
  all.forEach(m => {
    const otherId = m.from === req.user.id ? m.to : m.from;
    if (!conversations[otherId] || m.createdAt > conversations[otherId].createdAt) {
      conversations[otherId] = m;
    }
  });

  const result = Object.entries(conversations).map(([otherId, lastMsg]) => {
    const profile = db.get('profiles').find({ userId: otherId }).value();
    const unread = db.get('messages').filter(m => m.from === otherId && m.to === req.user.id && !m.read).value().length;
    return { otherId, profile, lastMsg, unread };
  });

  res.json(result.sort((a, b) => b.lastMsg.createdAt.localeCompare(a.lastMsg.createdAt)));
});

// ─────────────────────────────────────────────────────────────
//  VIBE ROOMS
// ─────────────────────────────────────────────────────────────

// GET /api/rooms
app.get('/api/rooms', (req, res) => {
  const rooms = db.get('rooms').value().map(r => ({
    ...r,
    occupants: onlineRooms[r.id] ? onlineRooms[r.id].size : 0,
  }));
  res.json(rooms);
});

// POST /api/rooms  — create custom room
app.post('/api/rooms', authRequired, (req, res) => {
  const { name, desc, tag } = req.body;
  if (!name) return res.status(400).json({ error: 'Room name required' });

  const room = {
    id: uuidv4(),
    name, desc: desc || '', tag: tag || 'General',
    createdBy: req.user.id,
    maxPeople: 20,
    createdAt: now(),
  };
  db.get('rooms').push(room).write();
  res.json(room);
});

// ─────────────────────────────────────────────────────────────
//  MOCK TEST / QUIZ RESULTS
// ─────────────────────────────────────────────────────────────

// POST /api/quiz/result
app.post('/api/quiz/result', authRequired, (req, res) => {
  const { subject, score, total, questions } = req.body;
  const result = {
    id: uuidv4(), userId: req.user.id,
    subject, score, total,
    pct: Math.round(score / total * 100),
    questions: questions || [],
    createdAt: now()
  };
  db.get('quiz_results').push(result).write();
  res.json(result);
});

// GET /api/quiz/results
app.get('/api/quiz/results', authRequired, (req, res) => {
  const results = db.get('quiz_results')
    .filter({ userId: req.user.id })
    .sortBy('createdAt')
    .reverse()
    .value();
  res.json(results);
});

// ─────────────────────────────────────────────────────────────
//  PROGRESS / SYLLABUS TRACKER
// ─────────────────────────────────────────────────────────────

// GET /api/progress
app.get('/api/progress', authRequired, (req, res) => {
  const progress = db.get('progress').find({ userId: req.user.id }).value();
  res.json(progress || { userId: req.user.id, checkedTopics: {}, streak: 0 });
});

// PUT /api/progress
app.put('/api/progress', authRequired, (req, res) => {
  const { checkedTopics } = req.body;
  const exists = db.get('progress').find({ userId: req.user.id }).value();

  if (exists) {
    db.get('progress').find({ userId: req.user.id })
      .assign({ checkedTopics, updatedAt: now() }).write();
  } else {
    db.get('progress').push({ userId: req.user.id, checkedTopics, streak: 0, createdAt: now(), updatedAt: now() }).write();
  }
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────
//  NOTIFICATIONS
// ─────────────────────────────────────────────────────────────

app.get('/api/notifications', authRequired, (req, res) => {
  const notifs = db.get('notifications')
    .filter({ userId: req.user.id })
    .sortBy('createdAt')
    .reverse()
    .take(50)
    .value();
  res.json(notifs);
});

app.patch('/api/notifications/:id/read', authRequired, (req, res) => {
  db.get('notifications').find({ id: req.params.id, userId: req.user.id }).assign({ read: true }).write();
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────
//  SOCKET.IO — Real-time messaging + Video signalling + Rooms
// ─────────────────────────────────────────────────────────────

// Track who is in which room { roomId -> Set of socketIds }
const onlineRooms = {};
// Track socket -> { userId, roomId }
const socketMeta = {};

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Authentication required'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  socketMeta[socket.id] = { userId };

  // Join personal room for notifications/DMs
  socket.join(`user:${userId}`);

  // Mark user online
  db.get('profiles').find({ userId }).assign({ isOnline: true, lastActive: now() }).write();
  io.emit('user:online', { userId });

  // ── DIRECT MESSAGES ──────────────────────────────────────
  socket.on('dm:send', ({ toUserId, content }) => {
    if (!content?.trim()) return;
    const msg = {
      id: uuidv4(),
      from: userId,
      to: toUserId,
      content: content.trim(),
      read: false,
      createdAt: now(),
    };
    db.get('messages').push(msg).write();

    // Send to recipient
    io.to(`user:${toUserId}`).emit('dm:new', msg);
    // Confirm to sender
    socket.emit('dm:new', msg);
  });

  socket.on('dm:read', ({ fromUserId }) => {
    db.get('messages')
      .filter({ from: fromUserId, to: userId, read: false })
      .each(m => { m.read = true; })
      .write();
    io.to(`user:${fromUserId}`).emit('dm:read', { byUserId: userId });
  });

  // ── VIBE ROOM CHAT ────────────────────────────────────────
  socket.on('room:join', ({ roomId }) => {
    // Leave previous room
    const prev = socketMeta[socket.id]?.roomId;
    if (prev) {
      socket.leave(`room:${prev}`);
      if (onlineRooms[prev]) onlineRooms[prev].delete(socket.id);
      io.to(`room:${prev}`).emit('room:left', { userId, name: socket.user.name });
      io.emit('room:occupants', { roomId: prev, count: onlineRooms[prev]?.size || 0 });
    }

    socket.join(`room:${roomId}`);
    if (!onlineRooms[roomId]) onlineRooms[roomId] = new Set();
    onlineRooms[roomId].add(socket.id);
    socketMeta[socket.id].roomId = roomId;

    socket.to(`room:${roomId}`).emit('room:joined', { userId, name: socket.user.name });
    io.emit('room:occupants', { roomId, count: onlineRooms[roomId].size });

    // Send last 50 messages
    const history = db.get('room_messages').filter({ roomId }).sortBy('createdAt').reverse().take(50).value().reverse();
    socket.emit('room:history', history);
  });

  socket.on('room:message', ({ roomId, content }) => {
    if (!content?.trim()) return;
    const msg = {
      id: uuidv4(), roomId,
      userId, name: socket.user.name,
      content: content.trim(),
      createdAt: now(),
    };
    db.get('room_messages').push(msg).write();
    io.to(`room:${roomId}`).emit('room:message', msg);
  });

  socket.on('room:leave', () => {
    const roomId = socketMeta[socket.id]?.roomId;
    if (roomId) {
      socket.leave(`room:${roomId}`);
      if (onlineRooms[roomId]) onlineRooms[roomId].delete(socket.id);
      io.to(`room:${roomId}`).emit('room:left', { userId, name: socket.user.name });
      io.emit('room:occupants', { roomId, count: onlineRooms[roomId]?.size || 0 });
      socketMeta[socket.id].roomId = null;
    }
  });

  // ── WebRTC VIDEO SIGNALLING ───────────────────────────────
  socket.on('webrtc:offer', ({ toUserId, offer }) => {
    io.to(`user:${toUserId}`).emit('webrtc:offer', { fromUserId: userId, fromName: socket.user.name, offer });
  });

  socket.on('webrtc:answer', ({ toUserId, answer }) => {
    io.to(`user:${toUserId}`).emit('webrtc:answer', { fromUserId: userId, answer });
  });

  socket.on('webrtc:ice', ({ toUserId, candidate }) => {
    io.to(`user:${toUserId}`).emit('webrtc:ice', { fromUserId: userId, candidate });
  });

  socket.on('webrtc:room:offer', ({ roomId, toSocketId, offer }) => {
    io.to(toSocketId).emit('webrtc:room:offer', { fromSocketId: socket.id, fromUserId: userId, fromName: socket.user.name, offer });
  });

  socket.on('webrtc:room:answer', ({ toSocketId, answer }) => {
    io.to(toSocketId).emit('webrtc:room:answer', { fromSocketId: socket.id, answer });
  });

  socket.on('webrtc:room:ice', ({ toSocketId, candidate }) => {
    io.to(toSocketId).emit('webrtc:room:ice', { fromSocketId: socket.id, candidate });
  });

  // ── DISCONNECT ────────────────────────────────────────────
  socket.on('disconnect', () => {
    db.get('profiles').find({ userId }).assign({ isOnline: false, lastActive: now() }).write();
    io.emit('user:offline', { userId });

    const roomId = socketMeta[socket.id]?.roomId;
    if (roomId && onlineRooms[roomId]) {
      onlineRooms[roomId].delete(socket.id);
      io.to(`room:${roomId}`).emit('room:left', { userId, name: socket.user.name });
      io.emit('room:occupants', { roomId, count: onlineRooms[roomId].size });
    }
    delete socketMeta[socket.id];
  });
});

// ─── SERVE FRONTEND ───────────────────────────────────────────
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'client/public', 'index.html'));
});

// ─── START ────────────────────────────────────────────────────
httpServer.listen(PORT, () => {
  console.log(`\n🟢 OLDOON backend running → http://localhost:${PORT}`);
  console.log(`📦 Database → ${path.join(dbDir, 'db.json')}`);
  console.log(`🔌 Socket.IO real-time enabled\n`);
});
