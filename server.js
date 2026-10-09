require('dotenv').config({ path: '/opt/netquery/.env' });
const nodemailer = require('nodemailer');
const express = require('express');
const axios = require('axios');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const ExcelJS = require('exceljs');
const path = require('path');
const fs = require('fs');
const FileStore = require('session-file-store')(session);
const app = express();
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      scriptSrcAttr: ["'unsafe-inline'"]
    }
  }
}));
app.use(cors({ origin: 'https://172.17.35.109', credentials: true }));
const PORT = process.env.PORT || 3000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ store: new FileStore({ path: './sessions', ttl: 1800 }), secret: process.env.SESSION_SECRET, resave: true, saveUninitialized: false, rolling: true, cookie: { secure: true, httpOnly: true, sameSite: 'lax', maxAge: 1800000 } }));
const USERS_FILE = './data/users.json';
const GRUPOS_FILE = './data/grupos.json';
const DB_FILE = './data/database.json';
const BACKUP_DIR = './data/backups';
function loadJSON(file) { if (!fs.existsSync(file)) return null; return JSON.parse(fs.readFileSync(file, 'utf8')); }
function saveJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

// ── NOTIFICACIONES EMAIL ─────────────────────────────────────────────────────
const _mailTransport = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS }
});
let _mailReady = false;
const _loginFallidosPorIP = {};
_mailTransport.verify((err) => {
  if (err) console.error('[Mail] Error de configuracion:', err.message);
  else { _mailReady = true; console.log('[Mail] Listo para enviar notificaciones'); }
});
async function sendAlert(asunto, cuerpo) {
  if (!_mailReady || !process.env.MAIL_TO) return;
  try {
    await _mailTransport.sendMail({
      from: '"Queulat Alertas" <' + process.env.MAIL_USER + '>',
      to: process.env.MAIL_TO,
      subject: '[Queulat] ' + asunto,
      html: '<div style="font-family:monospace;padding:20px;background:#0f172a;color:#e2e8f0;border-radius:8px">'
        + '<h2 style="color:#ef4444">⚠️ ' + asunto + '</h2>'
        + '<p>' + cuerpo + '</p>'
        + '<hr style="border-color:#334155">'
        + '<small style="color:#64748b">Queulat v3.2 — ' + new Date().toLocaleString('es-CL') + '</small>'
        + '</div>'
    });
    console.log('[Mail] Alerta enviada:', asunto);
  } catch(e) { console.error('[Mail] Error enviando alerta:', e.message); }
}

// ── VALIDACIÓN Y SANITIZACIÓN ─────────────────────────────────────────────────
function sanitizeText(val, maxLen) {
  if (val === null || val === undefined) return '';
  let s = String(val);
  s = s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  s = s.trim();
  if (maxLen && s.length > maxLen) s = s.slice(0, maxLen);
  return s;
}
function sanitizeObject(obj, maxLen) {
  if (!obj || typeof obj !== 'object') return {};
  const out = {};
  Object.keys(obj).forEach(k => {
    const cleanKey = sanitizeText(k, 100);
    if (!cleanKey) return;
    const v = obj[k];
    out[cleanKey] = (typeof v === 'string') ? sanitizeText(v, maxLen || 500) : v;
  });
  return out;
}
function sanitizeIP(val) {
  let s = sanitizeText(val, 50);
  if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(s)) return s;
  return s.replace(/[^0-9./]/g, '');
}
function sanitizeModelStrict(val) {
  const s = sanitizeText(val, 60);
  if (!/^[A-Za-z0-9_\-]+$/.test(s)) return null;
  return s;
}
function isValidUsername(val) {
  const s = sanitizeText(val, 60);
  return /^[A-Za-z0-9._\-]{3,60}$/.test(s);
}
if (!fs.existsSync('./data')) fs.mkdirSync('./data', { recursive: true });
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads', { recursive: true });
if (!fs.existsSync('./sessions')) fs.mkdirSync('./sessions', { recursive: true });
if (!fs.existsSync(USERS_FILE)) { const hash = bcrypt.hashSync('Admin1234!', 10); saveJSON(USERS_FILE, [{ id: 1, username: 'admin', password: hash, role: 'admin', nombre: 'Administrador', activo: true, mustChangePassword: false }]); }
if (!fs.existsSync(DB_FILE)) saveJSON(DB_FILE, []);
function requireAuth(req, res, next) { if (!req.session.user) return res.status(401).json({ error: 'No autorizado' }); next(); }
function requireAdmin(req, res, next) { if (!req.session.user || !['admin','superadmin'].includes(req.session.user.role)) return res.status(403).json({ error: 'Acceso denegado' }); next(); }
function requireSuperAdmin(req, res, next) { if (!req.session.user || req.session.user.role !== 'superadmin') return res.status(403).json({ error: 'Acceso denegado: se requiere superadmin' }); next(); }
function requireEditor(req, res, next) { if (!req.session.user || !['admin','superadmin'].includes(req.session.user.role)) return res.status(403).json({ error: 'Acceso denegado' }); next(); }
function requireN2OSuperAdmin(req, res, next) { const u = req.session.user; if (!u || !(u.role === 'superadmin' || u.grupo === 'n2')) return res.status(403).json({ error: 'Acceso denegado' }); next(); }
function loadGrupos() { return loadJSON(GRUPOS_FILE) || {}; }
function requirePermiso(pestana, accion) {
  return function(req, res, next) {
    const u = req.session.user;
    if (!u) return res.status(401).json({ error: 'No autorizado' });
    if (u.role === 'superadmin') return next();
    const grupos = loadGrupos();
    const g = grupos[u.grupo];
    if (!g || !g.permisos || !g.permisos[pestana] || !g.permisos[pestana][accion]) {
      return res.status(403).json({ error: 'Acceso denegado' });
    }
    next();
  };
}
app.get('/api/grupos', requireSuperAdmin, (req, res) => { res.json(loadGrupos()); });
app.put('/api/grupos', requireSuperAdmin, (req, res) => {
  const nuevo = req.body;
  if (!nuevo || typeof nuevo !== 'object') return res.json({ success: false, message: 'Datos invalidos' });
  const actual = loadGrupos();
  const CLAVES_PROHIBIDAS = ['superadmin', '__proto__', 'constructor', 'prototype'];
  Object.keys(nuevo).forEach(k => { if (!CLAVES_PROHIBIDAS.includes(k)) actual[k] = nuevo[k]; });
  saveJSON(GRUPOS_FILE, actual);
  logAudit(req, 'GRUPOS_EDITAR', 'Permisos actualizados');
  res.json({ success: true });
});
function calcularPermisos(u) {
  const grupos = loadGrupos();
  if (u.role === 'superadmin') return (grupos.superadmin && grupos.superadmin.permisos) || {};
  const g = grupos[u.grupo];
  return (g && g.permisos) || {};
}
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { success: false, message: 'Demasiados intentos, espera 15 minutos' } });
const apiLimiter = rateLimit({ windowMs: 60*1000, max: 200, standardHeaders: true, legacyHeaders: false, message: { success: false, message: 'Demasiadas solicitudes, intenta de nuevo en un momento' } });
app.use('/api/', apiLimiter);
app.post('/api/login', loginLimiter, (req, res) => { const { username, password } = req.body; if (!username || !password || !isValidUsername(username)) { logAudit(req, 'LOGIN_FALLIDO', 'Formato invalido: ' + sanitizeText(String(username||''), 60)); return res.json({ success: false, message: 'Usuario o contrasena incorrectos' }); } const users = loadJSON(USERS_FILE); const idx = users.findIndex(u => u.username === username && u.activo); if (idx === -1 || !bcrypt.compareSync(password, users[idx].passwordHash)) { logAudit(req, 'LOGIN_FALLIDO', 'Usuario: ' + username); const _ip = req.headers['x-real-ip'] || req.ip || ''; _loginFallidosPorIP[_ip] = (_loginFallidosPorIP[_ip] || 0) + 1; if (_loginFallidosPorIP[_ip] === 3) { sendAlert('Intentos fallidos de login', 'Se detectaron <strong>3 intentos fallidos</strong> desde IP <strong>' + _ip + '</strong> con usuario <strong>' + username + '</strong>.'); } return res.json({ success: false, message: 'Usuario o contrasena incorrectos' }); } const user = users[idx]; user.lastActivity = new Date().toISOString(); saveJSON(USERS_FILE, users); req.session.user = { id: user.id, username: user.username, role: user.role, grupo: user.grupo || (user.role==='superadmin'?'superadmin':'n2'), nombre: user.nombre, mustChangePassword: !!user.mustChangePassword }; const _ipLogin = req.headers['x-real-ip'] || req.ip || ''; delete _loginFallidosPorIP[_ipLogin]; logAudit(req, 'LOGIN_OK', ''); res.json({ success: true, user: { ...req.session.user, permisos: calcularPermisos(req.session.user) } }); });
app.post('/api/logout', (req, res) => { logAudit(req, 'LOGOUT', ''); req.session.destroy(() => res.json({ success: true })); });
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ ...req.session.user, permisos: calcularPermisos(req.session.user) });
});
app.post('/api/change-password', requireAuth, (req, res) => { const newPassword = sanitizeText(req.body.newPassword, 200); if (!newPassword || newPassword.length < 6) return res.json({ success: false, message: 'Minimo 6 caracteres' }); const users = loadJSON(USERS_FILE); const idx = users.findIndex(u => u.id === req.session.user.id); if (idx === -1) return res.json({ success: false, message: 'Usuario no encontrado' }); users[idx].passwordHash = bcrypt.hashSync(newPassword, 10); users[idx].mustChangePassword = false; saveJSON(USERS_FILE, users); req.session.user.mustChangePassword = false; logAudit(req, 'CAMBIO_PASSWORD_PROPIO', ''); res.json({ success: true }); });
const MULTISHEET_FILE = './data/multisheet.json';

// ── SUPERADMIN ───────────────────────────────────────────────────────────────
app.put('/api/usuarios/:id/rol', requireSuperAdmin, (req, res) => {
  const users = loadJSON(USERS_FILE);
  const idx = users.findIndex(u => u.id == req.params.id);
  if (idx === -1) return res.json({ success: false, message: 'Usuario no encontrado' });
  const nuevoRol = req.body.role;
  if (!['consulta','admin','superadmin'].includes(nuevoRol)) return res.json({ success: false, message: 'Rol invalido' });
  // No se puede quitar el rol superadmin al unico superadmin
  if (users[idx].role === 'superadmin' && nuevoRol !== 'superadmin') {
    const superadmins = users.filter(u => u.role === 'superadmin');
    if (superadmins.length <= 1) return res.json({ success: false, message: 'No puedes degradar al unico superadmin' });
  }
  users[idx].role = nuevoRol;
  saveJSON(USERS_FILE, users);
  logAudit(req, 'CAMBIO_ROL', 'Usuario: ' + users[idx].username + ' → ' + nuevoRol);
  res.json({ success: true });
});

// ── AUDITORÍA ────────────────────────────────────────────────────────────────
const AUDIT_FILE = './data/audit.json';
if (!fs.existsSync(AUDIT_FILE)) saveJSON(AUDIT_FILE, []);
function logAudit(req, accion, detalle) {
  try {
    const _rawLogs = loadJSON(AUDIT_FILE); const logs = Array.isArray(_rawLogs) ? _rawLogs : [];
    logs.push({
      id: Date.now() + Math.random().toString(36).slice(2,7),
      fecha: new Date().toISOString(),
      usuario: (req.session && req.session.user) ? req.session.user.username : ((req.body && req.body.username) || 'desconocido'),
      rol: (req.session && req.session.user) ? req.session.user.role : '-',
      accion,
      detalle: detalle || '',
      ip: req.headers['x-real-ip'] || req.ip || (req.connection && req.connection.remoteAddress) || ''
    });
    if (logs.length > 5000) logs.splice(0, logs.length - 5000);
    saveJSON(AUDIT_FILE, logs);
  } catch(e) { console.error('[Auditoria] Error:', e.message); }
}
const ADMIN_CREDS_FILE = './data/admin_creds.json';
if (!fs.existsSync(ADMIN_CREDS_FILE)) saveJSON(ADMIN_CREDS_FILE, {});
app.get('/api/admin-creds/:key', requireSuperAdmin, (req, res) => {
  const creds = loadJSON(ADMIN_CREDS_FILE) || {};
  const key = sanitizeText(req.params.key, 100);
  res.json(creds[key] || {});
});
app.post('/api/admin-creds', requireSuperAdmin, (req, res) => {
  const key = sanitizeText(req.body.key, 100);
  const usuario = sanitizeText(req.body.usuario, 200);
  const pass = sanitizeText(req.body.pass, 200);
  if (!key) return res.json({ success: false, message: 'Falta key' });
  const creds = loadJSON(ADMIN_CREDS_FILE) || {};
  creds[key] = { usuario, pass };
  saveJSON(ADMIN_CREDS_FILE, creds);
  logAudit(req, 'ADMIN_CREDS_GUARDAR', 'Key: ' + key);
  res.json({ success: true });
});

const AGENDA_CONFIG_FILE = './data/agenda_config.json';
if (!fs.existsSync(AGENDA_CONFIG_FILE)) saveJSON(AGENDA_CONFIG_FILE, {});
app.get('/api/agenda-config', requireAuth, (req, res) => {
  const config = loadJSON(AGENDA_CONFIG_FILE) || {};
  res.json(config);
});
app.post('/api/agenda-config', requireSuperAdmin, (req, res) => {
  const label = sanitizeText(req.body.label, 100);
  const colsRaw = sanitizeText(req.body.cols, 500);
  if (!label || !colsRaw) return res.json({ success: false, message: 'Faltan datos' });
  const cols = colsRaw.split(',').map(c => c.trim()).filter(Boolean);
  if (cols.length === 0) return res.json({ success: false, message: 'Debe indicar al menos una columna' });
  const key = label.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  if (!key) return res.json({ success: false, message: 'Nombre invalido' });
  const config = loadJSON(AGENDA_CONFIG_FILE) || {};
  if (config[key]) return res.json({ success: false, message: 'Ya existe una pestaña con ese nombre' });
  const sheetName = 'Agenda_' + label.trim();
  config[key] = { label: label.trim(), sheet: sheetName, cols };
  saveJSON(AGENDA_CONFIG_FILE, config);
  const ms = loadJSON(MULTISHEET_FILE) || {};
  if (!ms[sheetName]) ms[sheetName] = [];
  saveJSON(MULTISHEET_FILE, ms);
  invalidateMultisheetCache();
  logAudit(req, 'AGENDA_CREAR_PESTANA', 'Pestana: ' + label + ', Columnas: ' + cols.join(','));
  res.json({ success: true, key, config: config[key] });
});

const KMZ_INDEX_FILE = './data/kmz_index.json';
const KMZ_DIR = './uploads/kmz';
if (!fs.existsSync(KMZ_INDEX_FILE)) saveJSON(KMZ_INDEX_FILE, []);
if (!fs.existsSync(KMZ_DIR)) fs.mkdirSync(KMZ_DIR, { recursive: true });
const kmzUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, KMZ_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + path.basename(file.originalname))
  }),
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext === '.kmz') cb(null, true); else cb(new Error('Solo se permiten archivos .kmz'));
  },
  limits: { fileSize: 20 * 1024 * 1024 }
});
app.get('/api/kmz/search', requireAuth, (req, res) => {
  const q = sanitizeText(req.query.q || '', 200).trim().toUpperCase();
  const index = loadJSON(KMZ_INDEX_FILE) || [];
  if (!q) return res.json([]);
  const found = index.filter(r => (r.Codigo_Servicio || '').toUpperCase().includes(q) || (r.Cliente || '').toUpperCase().includes(q));
  res.json(found);
});
app.post('/api/kmz/upload', requireAdmin, kmzUpload.single('file'), (req, res) => {
  if (!req.file) return res.json({ success: false, message: 'No se recibio archivo' });
  const codigo = sanitizeText(req.body.codigo, 100).trim();
  const cliente = sanitizeText(req.body.cliente, 200).trim();
  if (!codigo) { fs.unlinkSync(req.file.path); return res.json({ success: false, message: 'El codigo de servicio es obligatorio' }); }
  const index = loadJSON(KMZ_INDEX_FILE) || [];
  const existente = index.find(r => (r.Codigo_Servicio || '').trim() === codigo);
  if (existente) {
    const oldPath = path.join(KMZ_DIR, existente.filename);
    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    existente.Cliente = cliente;
    existente.filename = req.file.filename;
    existente.originalName = req.file.originalname;
    existente.uploadedAt = new Date().toISOString();
  } else {
    index.push({ Codigo_Servicio: codigo, Cliente: cliente, filename: req.file.filename, originalName: req.file.originalname, uploadedAt: new Date().toISOString() });
  }
  saveJSON(KMZ_INDEX_FILE, index);
  logAudit(req, 'KMZ_SUBIR', 'Codigo: ' + codigo + ', Cliente: ' + cliente);
  res.json({ success: true });
});
app.get('/api/kmz/download/:codigo', requireAuth, (req, res) => {
  const codigo = sanitizeText(req.params.codigo, 100).trim();
  const index = loadJSON(KMZ_INDEX_FILE) || [];
  const item = index.find(r => (r.Codigo_Servicio || '').trim() === codigo);
  if (!item) return res.status(404).json({ success: false, message: 'No encontrado' });
  const filePath = path.join(KMZ_DIR, item.filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ success: false, message: 'Archivo no encontrado en disco' });
  res.download(filePath, item.originalName || item.filename);
});
app.delete('/api/kmz/:codigo', requireAdmin, (req, res) => {
  const codigo = sanitizeText(req.params.codigo, 100).trim();
  let index = loadJSON(KMZ_INDEX_FILE) || [];
  const item = index.find(r => (r.Codigo_Servicio || '').trim() === codigo);
  if (!item) return res.json({ success: false, message: 'No encontrado' });
  const filePath = path.join(KMZ_DIR, item.filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  index = index.filter(r => (r.Codigo_Servicio || '').trim() !== codigo);
  saveJSON(KMZ_INDEX_FILE, index);
  logAudit(req, 'KMZ_ELIMINAR', 'Codigo: ' + codigo);
  res.json({ success: true });
});

app.get('/api/auditoria', requireSuperAdmin, (req, res) => {
  const _rawLogs = loadJSON(AUDIT_FILE); const logs = Array.isArray(_rawLogs) ? _rawLogs : [];
  res.json(logs.slice().reverse().slice(0, 1000));
});

app.get('/api/sugerencias', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim().toUpperCase();
  if (q.length < 2) return res.json([]);
  const ms = loadJSON(MULTISHEET_FILE) || {};
  const sugerencias = [];
  Object.entries(ms).forEach(([sheet, rows]) => {
    if (sheet === 'BD_Clientes_OLT') return; // Se fusiona con BD_Servicios
    rows.forEach(row => {
      // Buscar coincidencia en CUALQUIER campo
      const match = Object.entries(row).some(([k, v]) =>
        (v || '').toString().toUpperCase().includes(q)
      );
      if (!match) return;
      // Obtener el codigo de la fila
      const codigoKey = Object.keys(row).find(k => k.toLowerCase().includes('codigo') || k.toLowerCase().includes('cod_'));
      const codigo = codigoKey ? (row[codigoKey] || '').toString().trim() : '';
      if (!codigo) return;
      // Campo descriptivo
      const descKey = Object.keys(row).find(k =>
        k.toLowerCase().includes('cliente') ||
        k.toLowerCase().includes('name') ||
        k.toLowerCase().includes('nombre')
      );
      const desc = descKey ? String(row[descKey] || '') : '';
      const comunaKey = Object.keys(row).find(k => k.toLowerCase().includes('comuna'));
      const comuna = comunaKey ? String(row[comunaKey] || '') : '';
      sugerencias.push({ codigo, desc, comuna, sheet: sheet.replace('BD_','') });
    });
  });
  const vistos = new Set();
  const unicos = sugerencias.filter(s => {
    if (vistos.has(s.codigo)) return false;
    vistos.add(s.codigo);
    return true;
  }).slice(0, 100);
  res.json(unicos);
});
// ── ÍNDICE EN MEMORIA ────────────────────────────────────────────────────────
let _msCache = null;
function getMultisheetCache() {
  if (!_msCache) _msCache = loadJSON(MULTISHEET_FILE) || {};
  return _msCache;
}
function invalidateMultisheetCache() { _msCache = null; }
// Precarga al arrancar
try { _msCache = loadJSON(MULTISHEET_FILE) || {}; } catch(e) {}

app.get('/api/consulta/:codigo', requireAuth, (req, res) => {
  const codigo = req.params.codigo.trim().toUpperCase();
  const ms = getMultisheetCache();
  const results = {};
  Object.entries(ms).forEach(([sheet, rows]) => {
    const found = rows.filter(row => {
      return Object.entries(row).some(([k, v]) => {
        if (!k.toLowerCase().includes('codigo') && !k.toLowerCase().includes('cod_')) return false;
        const val = (v || '').toString().trim().toUpperCase();
        return val === codigo || val.includes(codigo);
      });
    });
    if (found.length > 0) results[sheet] = found;
  });
  // Fibras Oscuras: buscar en todas las hojas (match en cualquier columna)
  const foData = loadJSON(FO_FILE) || {};
  Object.entries(foData).forEach(([sheet, rows]) => {
    const found = rows.filter(row =>
      Object.values(row).some(v => (v || '').toString().trim().toUpperCase().includes(codigo))
    );
    if (found.length > 0) results[sheet] = found;
  });
  if (Object.keys(results).length === 0) return res.json({ found: false });
  res.json({ found: true, data: results });
});
app.post('/api/datos', requireAdmin, (req, res) => { const db = loadJSON(DB_FILE); const nuevo = sanitizeObject(req.body, 500); if (!nuevo.CODIGO) return res.json({ success: false, message: 'El campo CODIGO es obligatorio' }); const existe = db.find(r => (r.CODIGO || '').toString().trim().toUpperCase() === nuevo.CODIGO.toString().trim().toUpperCase()); if (existe) return res.json({ success: false, message: 'Ya existe un registro con ese CODIGO' }); db.push(nuevo); saveJSON(DB_FILE, db); logAudit(req, 'DATOS_CREAR', 'CODIGO: ' + nuevo.CODIGO); res.json({ success: true }); });
app.put('/api/datos/:codigo', requireAdmin, (req, res) => { const db = loadJSON(DB_FILE); const codigo = sanitizeText(req.params.codigo, 100).trim().toUpperCase(); const cambios = sanitizeObject(req.body, 500); let updated = 0; const newDb = db.map(row => { if ((row.CODIGO || '').toString().trim().toUpperCase() === codigo) { updated++; return { ...row, ...cambios }; } return row; }); if (updated === 0) return res.json({ success: false, message: 'Registro no encontrado' }); saveJSON(DB_FILE, newDb); logAudit(req, 'DATOS_EDITAR', 'CODIGO: ' + codigo); res.json({ success: true, updated }); });
app.delete('/api/datos/:codigo', requireAdmin, (req, res) => { const db = loadJSON(DB_FILE); const codigo = sanitizeText(req.params.codigo, 100).trim().toUpperCase(); const newDb = db.filter(row => (row.CODIGO || '').toString().trim().toUpperCase() !== codigo); if (newDb.length === db.length) return res.json({ success: false, message: 'Registro no encontrado' }); saveJSON(DB_FILE, newDb); logAudit(req, 'DATOS_ELIMINAR', 'CODIGO: ' + codigo); res.json({ success: true }); });
app.get('/api/usuarios', requireSuperAdmin, (req, res) => { const users = loadJSON(USERS_FILE).map(u => ({ ...u, password: undefined, passwordHash: undefined })); res.json(users); });
app.post('/api/usuarios', requireSuperAdmin, (req, res) => { const username = sanitizeText(req.body.username, 60); const password = sanitizeText(req.body.password, 200); const nombre = sanitizeText(req.body.nombre, 100); const role = req.body.role; const temporal = req.body.temporal; if (!username || !password || !nombre || !role) return res.json({ success: false, message: 'Todos los campos son requeridos' }); if (!isValidUsername(username)) return res.json({ success: false, message: 'Usuario invalido: solo letras, numeros, punto y guion (3-60 caracteres)' }); if (password.length < 6) return res.json({ success: false, message: 'La contrasena debe tener minimo 6 caracteres' }); const users = loadJSON(USERS_FILE); if (users.find(u => u.username === username)) return res.json({ success: false, message: 'El usuario ya existe' }); const grupoNuevo = Object.keys(loadGrupos()).includes(req.body.grupo) ? req.body.grupo : 'n2'; users.push({ id: Date.now(), username, nombre, passwordHash: bcrypt.hashSync(password, 10), role: role === 'admin' ? 'admin' : 'consulta', grupo: grupoNuevo, activo: true, mustChangePassword: !!temporal }); saveJSON(USERS_FILE, users); logAudit(req, 'USUARIO_CREAR', 'Usuario: ' + username + ' (' + role + ')'); res.json({ success: true }); });
app.put('/api/usuarios/:id', requireSuperAdmin, (req, res) => { const users = loadJSON(USERS_FILE); const idx = users.findIndex(u => u.id == req.params.id); if (idx === -1) return res.json({ success: false, message: 'Usuario no encontrado' }); const nombre = sanitizeText(req.body.nombre, 100); const role = req.body.role; const activo = req.body.activo; const password = sanitizeText(req.body.password, 200); const temporal = req.body.temporal; if (password && password.length < 6) return res.json({ success: false, message: 'La contrasena debe tener minimo 6 caracteres' }); if (nombre) users[idx].nombre = nombre; if (role) users[idx].role = role; if (req.body.grupo && Object.keys(loadGrupos()).includes(req.body.grupo)) users[idx].grupo = req.body.grupo; if (activo !== undefined) users[idx].activo = activo; if (password) { users[idx].passwordHash = bcrypt.hashSync(password, 10); users[idx].mustChangePassword = !!temporal; } saveJSON(USERS_FILE, users); logAudit(req, 'USUARIO_EDITAR', 'Usuario: ' + users[idx].username); res.json({ success: true }); });
app.delete('/api/usuarios/:id', requireSuperAdmin, (req, res) => { let users = loadJSON(USERS_FILE); const target = users.find(u => u.id == req.params.id); if (!target) return res.json({ success: false, message: 'Usuario no encontrado' }); if (target.username === 'admin') return res.json({ success: false, message: 'No se puede eliminar el admin principal' }); users = users.filter(u => u.id != req.params.id); saveJSON(USERS_FILE, users); logAudit(req, 'USUARIO_ELIMINAR', 'Usuario: ' + target.username); res.json({ success: true }); });
app.post('/api/usuarios/:id/reset-password', requireSuperAdmin, (req, res) => { const password = sanitizeText(req.body.password, 200); if (!password || password.length < 6) return res.json({ success: false, message: 'Ingrese una contrasena temporal de minimo 6 caracteres' }); const users = loadJSON(USERS_FILE); const idx = users.findIndex(u => u.id == req.params.id); if (idx === -1) return res.json({ success: false, message: 'Usuario no encontrado' }); users[idx].passwordHash = bcrypt.hashSync(password, 10); users[idx].mustChangePassword = true; saveJSON(USERS_FILE, users); logAudit(req, 'USUARIO_RESET_PASSWORD', 'Usuario: ' + users[idx].username); res.json({ success: true }); });
const storage = multer.diskStorage({ destination: (req, file, cb) => cb(null, './uploads/'), filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)) });
const upload = multer({ storage, fileFilter: (req, file, cb) => { const ext = path.extname(file.originalname).toLowerCase(); if (['.xlsx','.xls','.csv'].includes(ext)) { cb(null, true); } else { cb(new Error('Solo se permiten archivos .xlsx, .xls o .csv')); } }, limits: { fileSize: 50*1024*1024 } });
app.post('/api/upload', requireSuperAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.json({ success: false, message: 'No se recibio archivo' });
  try {
    const ext = path.extname(req.file.originalname).toLowerCase();
    const workbook = new ExcelJS.Workbook();
    if (ext === '.csv') { await workbook.csv.readFile(req.file.path); }
    else { await workbook.xlsx.readFile(req.file.path); }
    const multisheet = loadJSON(MULTISHEET_FILE) || {};
    let totalRows = 0;
    workbook.eachSheet((worksheet, sheetId) => {
      // Hoja especial con dos tablas lado a lado
      if (worksheet.name === 'BD_Fw-Onpremise') {
        const row3 = worksheet.getRow(3);
        const headersLeft = [], headersRight = [];
        // Columnas A-C (1-3) = Internet Seguro, E-G (5-7) = On Premise
        row3.eachCell({ includeEmpty: true }, (cell, col) => {
          if (col >= 1 && col <= 3) headersLeft[col-1] = cell.value || null;
          if (col >= 5 && col <= 7) headersRight[col-5] = cell.value || null;
        });
        const dataLeft = [], dataRight = [];
        worksheet.eachRow((row, rowNumber) => {
          if (rowNumber <= 3) return;
          const objL = {}, objR = {};
          row.eachCell({ includeEmpty: true }, (cell, col) => {
            if (col >= 1 && col <= 3 && headersLeft[col-1]) objL[headersLeft[col-1]] = cell.value !== null ? String(cell.value) : '';
            if (col >= 5 && col <= 7 && headersRight[col-5]) objR[headersRight[col-5]] = cell.value !== null ? String(cell.value) : '';
          });
          if (Object.values(objL).some(v => v !== '')) dataLeft.push(objL);
          if (Object.values(objR).some(v => v !== '')) dataRight.push(objR);
        });
        multisheet['BD_Fw_Internet_Seguro'] = dataLeft;
        multisheet['BD_Fw_On_Premise'] = dataRight;
        totalRows += dataLeft.length + dataRight.length;
        return;
      }
      const headers = [];
      worksheet.getRow(1).eachCell((cell) => headers.push(cell.value));
      if (headers.filter(Boolean).length === 0) return;
      const data = [];
      worksheet.eachRow((row, rowNumber) => {
        if (rowNumber === 1) return;
        const obj = {};
        row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
          if (headers[colNumber-1]) { let val = cell.value; if (val !== null && val !== undefined) { if (typeof val === "object") { if (val.richText) val = val.richText.map(r => r.text || "").join(""); else if (val.result !== undefined) val = String(val.result); else if (val.text) val = String(val.text); else val = String(val); } else { val = String(val); } } else { val = ""; } obj[headers[colNumber-1]] = val; }
        });
        if (Object.values(obj).some(v => v !== '')) data.push(obj);
      });
      multisheet[worksheet.name] = data;
      totalRows += data.length;
    });
    fs.unlinkSync(req.file.path);
    saveJSON(MULTISHEET_FILE, multisheet);
    invalidateMultisheetCache();
    const firstSheet = multisheet[Object.keys(multisheet)[0]] || [];
    saveJSON(DB_FILE, firstSheet);
    res.json({ success: true, rows: totalRows, sheets: Object.keys(multisheet).length, columns: firstSheet.length > 0 ? Object.keys(firstSheet[0]) : [] });
  } catch(e) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.json({ success: false, message: 'Error: ' + e.message });
  }
});
app.get('/api/db/info', requireAuth, (req, res) => { const db = loadJSON(DB_FILE); res.json({ rows: db.length, columns: db.length > 0 ? Object.keys(db[0]) : [] }); });
app.post('/api/db/backup', requireSuperAdmin, async (req, res) => {
  try {
    const multisheet = loadJSON(MULTISHEET_FILE);
    const ts = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
    const filename = 'backup-' + ts + '.xlsx';
    const xlsxFile = path.join(BACKUP_DIR, filename);
    const workbook = new ExcelJS.Workbook();
    let totalRows = 0;
    for (const [sheetName, data] of Object.entries(multisheet)) {
      if (!Array.isArray(data) || data.length === 0) continue;
      const worksheet = workbook.addWorksheet(sheetName);
      const columns = Object.keys(data[0]);
      worksheet.columns = columns.map(col => ({ header: col, key: col, width: 22 }));
      data.forEach(row => worksheet.addRow(row));
      totalRows += data.length;
    }
    await workbook.xlsx.writeFile(xlsxFile);
    res.json({ success: true, file: filename, rows: totalRows });
  } catch(e) { res.json({ success: false, message: e.message }); }
});
app.get('/api/db/backups', requireSuperAdmin, (req, res) => { const files = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.xlsx')).map(f => ({ name: f, size: fs.statSync(path.join(BACKUP_DIR, f)).size })).reverse(); res.json(files); });
app.get('/api/db/backup/download/:filename', requireSuperAdmin, (req, res) => { const filename = path.basename(req.params.filename); const file = path.join(BACKUP_DIR, filename); if (!fs.existsSync(file)) return res.status(404).json({ error: 'No encontrado' }); res.download(file); });
app.delete('/api/db', requireSuperAdmin, (req, res) => { saveJSON(DB_FILE, []); res.json({ success: true }); });

// --- ESMAX ---
const { exec } = require('child_process');
const ESMAX_FILE = './data/esmax_sites.json';
if (!fs.existsSync(ESMAX_FILE)) saveJSON(ESMAX_FILE, []);

// Obtener sitios
app.get('/api/esmax/sites', requireAuth, (req, res) => {
  res.json(loadJSON(ESMAX_FILE) || []);
});

// Agregar sitio
app.post('/api/esmax/sites', requireAdmin, (req, res) => {
  const nombre = sanitizeText(req.body.nombre, 100);
  const ip = sanitizeIP(req.body.ip);
  if (!nombre || !ip) return res.json({ success: false, message: 'Nombre e IP requeridos' });
  const sites = loadJSON(ESMAX_FILE) || [];
  if (sites.find(s => s.ip === ip)) return res.json({ success: false, message: 'IP ya existe' });
  sites.push({ id: Date.now(), nombre, ip });
  saveJSON(ESMAX_FILE, sites);
  res.json({ success: true });
});

// Eliminar sitio
app.delete('/api/esmax/sites/:id', requireAdmin, (req, res) => {
  let sites = loadJSON(ESMAX_FILE) || [];
  const before = sites.length;
  sites = sites.filter(s => s.id != req.params.id);
  if (sites.length === before) return res.json({ success: false, message: 'Sitio no encontrado' });
  saveJSON(ESMAX_FILE, sites);
  res.json({ success: true });
});

// Ping a un sitio
app.get('/api/esmax/ping/:ip', requireAuth, (req, res) => {
  const ip = req.params.ip.replace(/[^0-9.]/g, '');
  exec('ping -c 5 -W 2 ' + ip, (err, stdout) => {
    const lines = stdout || '';
    const lossMatch = lines.match(/(\d+)% packet loss/);
    const rttMatch = lines.match(/rtt[^=]*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)/);
    const loss = lossMatch ? parseInt(lossMatch[1]) : 100;
    const avg = rttMatch ? parseFloat(rttMatch[2]) : null;
    let estado = 'rojo';
    if (loss === 0 && avg !== null && avg < 100) estado = 'verde';
    else if (loss < 50) estado = 'amarillo';
    if (estado === 'rojo') {
      sendAlert('Equipo caido: ' + ip, 'El equipo <strong>' + ip + '</strong> no responde al ping. Perdida: <strong>' + loss + '%</strong>. Hora: ' + new Date().toLocaleString('es-CL'));
    }
    res.json({ ip, loss, avg, estado, raw: lines });
  });
});

// Chequeo rapido de puertos abiertos (para conexion SSH/Telnet desde la UI)
app.get('/api/network/portcheck/:ip', requireAuth, (req, res) => {
  const net = require('net');
  const ip = String(req.params.ip || '').trim().replace(/\/\d{1,2}$/, '');
  const oct = ip.split('.').map(Number);
  if (!net.isIPv4(ip) || oct[0] === 0 || oct[0] === 127 || oct[0] >= 224 || (oct[0] === 169 && oct[1] === 254)) {
    return res.json({ success: false, message: 'IP invalida' });
  }
  const puertos = [22, 2022, 23, 2023];
  const resultados = {};
  let pendientes = puertos.length;
  puertos.forEach(port => {
    const socket = new net.Socket();
    let done = false;
    const finalizar = (abierto) => {
      if (done) return;
      done = true;
      resultados[port] = abierto;
      socket.destroy();
      pendientes--;
      if (pendientes === 0) res.json({ success: true, ip, resultados });
    };
    socket.setTimeout(800);
    socket.once('connect', () => finalizar(true));
    socket.once('timeout', () => finalizar(false));
    socket.once('error', () => finalizar(false));
    socket.connect(port, ip);
  });
});

// Backup Esmax con fecha
const ESMAX_BACKUP_DIR = './data/esmax_backups';
if (!fs.existsSync(ESMAX_BACKUP_DIR)) fs.mkdirSync(ESMAX_BACKUP_DIR, { recursive: true });

app.post('/api/esmax/backup', requireAdmin, async (req, res) => {
  try {
    const sites = loadJSON(ESMAX_FILE) || [];
    const ts = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
    const filename = 'esmax-backup-' + ts + '.xlsx';
    const xlsxFile = path.join(ESMAX_BACKUP_DIR, filename);
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Sitios');
    worksheet.columns = [
      { header: 'Nombre', key: 'nombre', width: 30 },
      { header: 'IP', key: 'ip', width: 20 }
    ];
    sites.forEach(s => worksheet.addRow(s));
    await workbook.xlsx.writeFile(xlsxFile);
    // Mantener solo los ultimos 30 dias
    const files = fs.readdirSync(ESMAX_BACKUP_DIR)
      .filter(f => f.startsWith('esmax-backup-'))
      .sort();
    if (files.length > 30) {
      files.slice(0, files.length - 30).forEach(f => {
        fs.unlinkSync(path.join(ESMAX_BACKUP_DIR, f));
      });
    }
    res.json({ success: true, file: filename });
  } catch(e) {
    console.error('[Fortinet upgrade-path error]', e.message, e.stack); res.json({ success: false, message: e.message });
  }
});


const ICMP_FILE = './data/icmp_sites.json';
if (!fs.existsSync(ICMP_FILE)) saveJSON(ICMP_FILE, []);
app.get('/api/icmp/sites', requireAuth, (req, res) => {
  const sites = loadJSON(ICMP_FILE) || [];
  res.json(sites);
});
app.post('/api/icmp/sites', requireAdmin, (req, res) => {
  const nombre = sanitizeText(req.body.nombre, 150);
  const ip = sanitizeIP(req.body.ip || '');
  const codigo = sanitizeText(req.body.codigo, 100);
  const cliente = sanitizeText(req.body.cliente, 150);
  const zona = sanitizeText(req.body.zona, 100);
  const requiereVpn = !!req.body.requiereVpn;
  if (!ip) return res.json({ success: false, message: 'La IP es obligatoria' });
  const sites = loadJSON(ICMP_FILE) || [];
  const nuevo = { id: Date.now().toString(36) + Math.random().toString(36).slice(2,8), nombre: nombre || ip, ip, codigo, cliente, zona, requiereVpn, avg: null, loss: null, estado: 'gris' };
  sites.push(nuevo);
  saveJSON(ICMP_FILE, sites);
  logAudit(req, 'ICMP_AGREGAR', 'Nombre: ' + nuevo.nombre + ', IP: ' + ip);
  res.json({ success: true, site: nuevo });
});
app.put('/api/icmp/sites/:id', requireAuth, (req, res) => {
  const sites = loadJSON(ICMP_FILE) || [];
  const idx = sites.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.json({ success: false, message: 'Equipo no encontrado' });
  const cambios = {};
  if (req.body.avg !== undefined) cambios.avg = req.body.avg;
  if (req.body.loss !== undefined) cambios.loss = req.body.loss;
  if (req.body.estado !== undefined) cambios.estado = sanitizeText(req.body.estado, 20);
  sites[idx] = { ...sites[idx], ...cambios };
  saveJSON(ICMP_FILE, sites);
  if (cambios.avg !== undefined || cambios.loss !== undefined || cambios.estado !== undefined) {
    const hist = loadJSON(ICMP_HIST_FILE) || {};
    if (!hist[req.params.id]) hist[req.params.id] = [];
    hist[req.params.id].push({ avg: cambios.avg, loss: cambios.loss, estado: cambios.estado, hora: new Date().toLocaleTimeString('es-CL'), ts: Date.now() });
    const hace24h = Date.now() - 24 * 60 * 60 * 1000;
    hist[req.params.id] = hist[req.params.id].filter(e => (e.ts || 0) > hace24h);
    if (hist[req.params.id].length > 100) hist[req.params.id] = hist[req.params.id].slice(-100);
    saveJSON(ICMP_HIST_FILE, hist);
  }
  res.json({ success: true });
});
app.delete('/api/icmp/sites/:id', requireAdmin, (req, res) => {
  let sites = loadJSON(ICMP_FILE) || [];
  const target = sites.find(s => s.id === req.params.id);
  if (!target) return res.json({ success: false, message: 'Equipo no encontrado' });
  sites = sites.filter(s => s.id !== req.params.id);
  saveJSON(ICMP_FILE, sites);
  logAudit(req, 'ICMP_ELIMINAR', 'Nombre: ' + target.nombre + ', IP: ' + target.ip);
  res.json({ success: true });
});
const ICMP_HIST_FILE = './data/icmp_historico.json';
if (!fs.existsSync(ICMP_HIST_FILE)) saveJSON(ICMP_HIST_FILE, {});
app.get('/api/icmp/historico', requireAuth, (req, res) => {
  res.json(loadJSON(ICMP_HIST_FILE) || {});
});
app.post('/api/icmp/historico', requireAuth, (req, res) => {
  const { id, avg, loss, estado, hora } = req.body;
  const hist = loadJSON(ICMP_HIST_FILE) || {};
  if (!hist[id]) hist[id] = [];
  hist[id].push({ avg, loss, estado, hora, ts: Date.now() });
  const hace24h = Date.now() - 24 * 60 * 60 * 1000;
  hist[id] = hist[id].filter(e => (e.ts || 0) > hace24h);
  if (hist[id].length > 100) hist[id] = hist[id].slice(-100);
  saveJSON(ICMP_HIST_FILE, hist);
  res.json({ success: true });
});
// --- BUSCADOR IP ---
const IP_FILE = './data/ipdb.json';
const IP_BACKUP_DIR = './data/ipdb_backups';
if (!fs.existsSync(IP_FILE)) saveJSON(IP_FILE, []);
if (!fs.existsSync(IP_BACKUP_DIR)) fs.mkdirSync(IP_BACKUP_DIR, { recursive: true });

app.get('/api/ipdb', requireAuth, (req, res) => {
  const db = loadJSON(IP_FILE) || [];
  const q = (req.query.q || '').trim().toUpperCase();
  if (!q) return res.json([]);
  const result = db.filter(r =>
    String(r.IP||'').toUpperCase().includes(q) ||
    String(r.Equipo||'').toUpperCase().includes(q)
  );
  res.json(result);
});

app.post('/api/ipdb', requireAdmin, (req, res) => {
  const db = loadJSON(IP_FILE) || [];
  const nuevo = sanitizeObject(req.body, 300);
  if (nuevo.IP) nuevo.IP = sanitizeIP(nuevo.IP);
  if (!nuevo.IP && !nuevo.Equipo) return res.json({ success: false, message: 'IP o Equipo requerido' });
  db.push({ id: Date.now(), ...nuevo });
  saveJSON(IP_FILE, db);
  logAudit(req, 'IPDB_CREAR', nuevo.IP || nuevo.Equipo || '');
  res.json({ success: true });
});

app.put('/api/ipdb/:id', requireSuperAdmin, (req, res) => {
  const db = loadJSON(IP_FILE) || [];
  const idx = db.findIndex(r => r.id == req.params.id);
  if (idx === -1) return res.json({ success: false, message: 'No encontrado' });
  const cambios = sanitizeObject(req.body, 300);
  if (cambios.IP) cambios.IP = sanitizeIP(cambios.IP);
  db[idx] = { ...db[idx], ...cambios };
  saveJSON(IP_FILE, db);
  logAudit(req, 'IPDB_EDITAR', db[idx].IP || db[idx].Equipo || ('ID: ' + req.params.id));
  res.json({ success: true });
});

app.delete('/api/ipdb/:id', requireSuperAdmin, (req, res) => {
  let db = loadJSON(IP_FILE) || [];
  const target = db.find(r => r.id == req.params.id);
  if (!target) return res.json({ success: false, message: 'Registro no encontrado' });
  db = db.filter(r => r.id != req.params.id);
  saveJSON(IP_FILE, db);
  logAudit(req, 'IPDB_ELIMINAR', target.IP || target.Equipo || '');
  res.json({ success: true });
});

const ipdbUpload = multer({ storage: multer.diskStorage({
  destination: (req, file, cb) => cb(null, './uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
}), fileFilter: (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  cb(null, ['.xlsx','.xls','.csv'].includes(ext));
}, limits: { fileSize: 50*1024*1024 } });

app.post('/api/ipdb/upload', requireAdmin, ipdbUpload.single('file'), async (req, res) => {
  if (!req.file) return res.json({ success: false, message: 'No se recibio archivo' });
  try {
    const workbook = new ExcelJS.Workbook();
    const ext = path.extname(req.file.originalname).toLowerCase();
    if (ext === '.csv') await workbook.csv.readFile(req.file.path);
    else await workbook.xlsx.readFile(req.file.path);
    const worksheet = workbook.getWorksheet(1);
    const headers = [];
    worksheet.getRow(1).eachCell(cell => headers.push(cell.value));
    const data = [];
    worksheet.eachRow((row, rowNumber) => {
      if (rowNumber === 1) return;
      const obj = { id: Date.now() + rowNumber };
      row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
        obj[headers[colNumber - 1]] = cell.value !== null ? cell.value : '';
      });
      data.push(obj);
    });
    fs.unlinkSync(req.file.path);
    saveJSON(IP_FILE, data);
    res.json({ success: true, rows: data.length });
  } catch(e) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.json({ success: false, message: e.message });
  }
});

app.post('/api/ipdb/backup', requireAdmin, async (req, res) => {
  try {
    const db = loadJSON(IP_FILE) || [];
    const ts = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
    const filename = 'ipdb-backup-' + ts + '.xlsx';
    const xlsxFile = path.join(IP_BACKUP_DIR, filename);
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('IPdb');
    if (db.length > 0) {
      const cols = Object.keys(db[0]);
      worksheet.columns = cols.map(c => ({ header: c, key: c, width: 20 }));
      db.forEach(row => worksheet.addRow(row));
    }
    await workbook.xlsx.writeFile(xlsxFile);
    // Mantener max 10 backups
    const files = fs.readdirSync(IP_BACKUP_DIR)
      .filter(f => f.startsWith('ipdb-backup-'))
      .sort();
    if (files.length > 10) {
      files.slice(0, files.length - 10).forEach(f => {
        fs.unlinkSync(path.join(IP_BACKUP_DIR, f));
      });
    }
    res.json({ success: true, file: filename, rows: db.length });
  } catch(e) {
    res.json({ success: false, message: e.message });
  }
});

app.get('/api/ipdb/download', requireAdmin, async (req, res) => {
  try {
    const db = loadJSON(IP_FILE) || [];
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('IPdb');
    if (db.length > 0) {
      const cols = Object.keys(db[0]).filter(c => c !== 'id');
      worksheet.columns = cols.map(c => ({ header: c, key: c, width: 20 }));
      db.forEach(row => worksheet.addRow(row));
    }
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=ipdb-export.xlsx');
    await workbook.xlsx.write(res);
    res.end();
  } catch(e) { res.status(500).json({ error: 'Error interno del servidor' }); }
});

app.delete('/api/ipdb/all', requireSuperAdmin, (req, res) => {
  saveJSON(IP_FILE, []);
  res.json({ success: true });
});

app.get('/api/ipdb/search', requireAuth, (req, res) => {
  const db = loadJSON(IP_FILE) || [];
  const q = (req.query.q || '').trim().toUpperCase();
  if (!q) return res.json([]);
  const results = db.filter(row =>
    Object.values(row).some(v => v !== null && v !== undefined && v.toString().toUpperCase().includes(q))
  ).slice(0, 50);
  res.json(results);
});
app.get('/api/ipdb/info', requireAuth, (req, res) => {
  const db = loadJSON(IP_FILE) || [];
  const columns = db.length > 0 ? Object.keys(db[0]).filter(k=>k && k!=='id' && k!=='undefined') : [];
  res.json({ rows: db.length, columns });
});

// Historico de pings
const ESMAX_HIST_FILE = './data/esmax_historico.json';
if (!fs.existsSync(ESMAX_HIST_FILE)) saveJSON(ESMAX_HIST_FILE, {});
app.get('/api/esmax/historico', requireAuth, (req, res) => {
  res.json(loadJSON(ESMAX_HIST_FILE) || {});
});
app.post('/api/esmax/historico', requireAuth, (req, res) => {
  const { id, avg, loss, estado, hora } = req.body;
  const hist = loadJSON(ESMAX_HIST_FILE) || {};
  if (!hist[id]) hist[id] = [];
  // Guardar con timestamp para limpieza por tiempo
  hist[id].push({ avg, loss, estado, hora, ts: Date.now() });
  // Mantener solo ultimas 24 horas y max 100 entradas
  const hace24h = Date.now() - 24 * 60 * 60 * 1000;
  hist[id] = hist[id].filter(e => (e.ts || 0) > hace24h);
  if (hist[id].length > 100) hist[id] = hist[id].slice(-100);
  saveJSON(ESMAX_HIST_FILE, hist);
  res.json({ success: true });
});

// ── BACKUPS PANORAMA ──────────────────────────────────────────────────────────
const PALO_BACKUP_DIR = '/opt/paloalto-backup';
app.get('/api/palo/backups', requireAuth, (req, res) => {
  try {
    const files = fs.readdirSync(PALO_BACKUP_DIR)
      .filter(f => f.endsWith('.xml'))
      .map(f => {
        const stat = fs.statSync(path.join(PALO_BACKUP_DIR, f));
        return { name: f, size: stat.size, fecha: stat.mtime };
      })
      .sort((a, b) => new Date(b.fecha) - new Date(a.fecha));
    res.json(files);
  } catch(e) { res.json([]); }
});
app.get('/api/palo/backup/download/:filename', requireN2OSuperAdmin, (req, res) => {
  const file = path.join(PALO_BACKUP_DIR, path.basename(req.params.filename));
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'No encontrado' });
  res.download(file);
});

app.get('/api/hoja/:sheet', requireAuth, (req, res) => {
  const ms = loadJSON(MULTISHEET_FILE) || {};
  const sheet = Object.keys(ms).find(k => k === req.params.sheet);
  if (!sheet) return res.json([]);
  res.json(ms[sheet]);
});


app.post('/api/multisheet', requireAdmin, (req, res) => {
  const { sheet, data } = req.body;
  if(!sheet || !data) return res.json({ success: false, message: 'Datos incompletos' });
  const ms = loadJSON(MULTISHEET_FILE) || {};
  if(!ms[sheet]) ms[sheet] = [];
  ms[sheet].push(data);
  saveJSON(MULTISHEET_FILE, ms);
  invalidateMultisheetCache();
  logAudit(req, 'MULTISHEET_CREAR', 'Hoja: ' + sheet);
  res.json({ success: true });
});

app.put('/api/multisheet', requireAdmin, (req, res) => {
  const { sheet, keyField, keyValue, data } = req.body;
  if(!sheet || !keyField || keyValue===undefined || keyValue===null || !data) return res.json({ success: false, message: 'Datos incompletos' });
  const ms = loadJSON(MULTISHEET_FILE) || {};
  if(!ms[sheet]) return res.json({ success: false, message: 'Hoja no encontrada' });
  let updated = 0;
  ms[sheet] = ms[sheet].map(row => {
    if((row[keyField]||'').toString().trim() === keyValue.toString().trim()){ updated++; return { ...row, ...data }; }
    return row;
  });
  if(updated === 0){ logAudit(req, 'MULTISHEET_EDITAR_FALLIDO', 'Hoja: ' + sheet + ', ' + keyField + ': ' + keyValue + ' (no encontrado)'); return res.json({ success: false, message: 'Registro no encontrado (' + keyField + ': ' + keyValue + ')' }); }
  saveJSON(MULTISHEET_FILE, ms);
  invalidateMultisheetCache();
  logAudit(req, 'MULTISHEET_EDITAR', 'Hoja: ' + sheet + ', ' + keyField + ': ' + keyValue);
  res.json({ success: true, updated });
});

app.delete('/api/multisheet', requireAdmin, (req, res) => {
  const { sheet, keyField, keyValue } = req.body;
  const ms = loadJSON(MULTISHEET_FILE) || {};
  if(!ms[sheet]) return res.json({ success: false, message: 'Hoja no encontrada' });
  const antes = ms[sheet].length;
  ms[sheet] = ms[sheet].filter(row => (row[keyField]||'').toString().trim() !== keyValue.toString().trim());
  if(ms[sheet].length === antes){ logAudit(req, 'MULTISHEET_ELIMINAR_FALLIDO', 'Hoja: ' + sheet + ', ' + keyField + ': ' + keyValue + ' (no encontrado)'); return res.json({ success: false, message: 'Registro no encontrado' }); }
  saveJSON(MULTISHEET_FILE, ms);
  invalidateMultisheetCache();
  logAudit(req, 'MULTISHEET_ELIMINAR', 'Hoja: ' + sheet + ', ' + keyField + ': ' + keyValue);
  res.json({ success: true });
});


// ── BD_IPO ────────────────────────────────────────────────────────────────────
app.get('/api/ipo/search', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim().toUpperCase();
  const ms = loadJSON(MULTISHEET_FILE) || {};
  const rows = ms['BD_Ipo'] || ms['BD_IPO'] || ms['BD_ipo'] || [];
  if (!q) return res.json(rows.slice(0, 500));
  const result = rows.filter(row =>
    Object.values(row).some(v => (v || '').toString().toUpperCase().includes(q))
  );
  res.json(result.slice(0, 500));
});
app.get('/api/cucm/search', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim().toUpperCase();
  const ms = loadJSON(MULTISHEET_FILE) || {};
  const rows = ms['BD_Cucm'] || [];
  if (!q) return res.json(rows.slice(0, 500));
  const result = rows.filter(row =>
    Object.values(row).some(v => (v || '').toString().toUpperCase().includes(q))
  );
  res.json(result.slice(0, 500));
});
app.get('/api/webex/search', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim().toUpperCase();
  const ms = loadJSON(MULTISHEET_FILE) || {};
  const rows = ms['BD_Webex'] || [];
  if (!q) return res.json(rows.slice(0, 500));
  const result = rows.filter(row =>
    Object.values(row).some(v => (v || '').toString().toUpperCase().includes(q))
  );
  res.json(result.slice(0, 500));
});

// ── BACKUP GOOGLE DRIVE ──────────────────────────────────────────────────────
app.post('/api/backup/drive', requireSuperAdmin, (req, res) => {
  const { exec } = require('child_process');
  exec('/home/ubuntu/backup_queulat.sh', (error, stdout, stderr) => {
    if (error) return res.json({ success: false, message: stderr || error.message });
    res.json({ success: true, message: stdout.trim() });
  });
});

// ── FIBRAS OSCURAS ───────────────────────────────────────────────────────────
const FO_FILE = './data/fo_parsed.json';
app.get('/api/fo/sheets', requireAuth, (req, res) => {
  const data = loadJSON(FO_FILE) || {};
  res.json(Object.keys(data).map(name => ({ name, count: data[name].length })));
});
app.get('/api/fo/:sheet', requireAuth, (req, res) => {
  const data = loadJSON(FO_FILE) || {};
  const sheet = decodeURIComponent(req.params.sheet);
  if(!data[sheet]) return res.json([]);
  const q = (req.query.q || '').trim().toUpperCase();
  if(!q) return res.json(data[sheet]);
  res.json(data[sheet].filter(row =>
    Object.values(row).some(v => (v||'').toString().toUpperCase().includes(q))
  ));
});
app.post('/api/fo/reload', requireAdmin, (req, res) => {
  const { execSync } = require('child_process');
  try {
    execSync('python3 /opt/netquery/fo_parser.py');
    res.json({ success: true });
  } catch(e) { res.json({ success: false, message: e.message }); }
});

// ── FORTINET UPGRADE PATH ────────────────────────────────────────────────────
const FORTINET_CACHE_FILE = './data/fortinet_cache.json';
if (!fs.existsSync(FORTINET_CACHE_FILE)) saveJSON(FORTINET_CACHE_FILE, {});
const _fortinetCache = (() => { try { return loadJSON(FORTINET_CACHE_FILE) || {}; } catch(e) { return {}; } })();
app.post('/api/fortinet/upgrade-path', requireAuth, async (req, res) => {
  const { model, current_version, target_version } = req.body;
  if (!model || !current_version || !target_version)
    return res.json({ success: false, message: 'Faltan parámetros' });
  const cacheKey = model+'|'+current_version+'|'+target_version;
  if (_fortinetCache[cacheKey]) return res.json(_fortinetCache[cacheKey]);
  try {
    const https = require('https');
    const postData = 'product_slug=fortigate&model='+encodeURIComponent(model)+'&current_version='+encodeURIComponent(current_version)+'&target_version='+encodeURIComponent(target_version);
    const options = {
      hostname: 'docs.fortinet.com',
      path: '/upgrade-tool/upgrade-path',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    const data = await new Promise((resolve, reject) => {
      const req2 = https.request(options, r => {
        let body = '';
        r.on('data', chunk => body += chunk);
        r.on('end', () => resolve(body));
      });
      req2.on('error', reject);
      req2.write(postData);
      req2.end();
    });
    if(!data || data.trim() === '') return res.json({ success: false, message: 'Respuesta vacía de Fortinet' });
    if(!data || data.trim() === '') return res.json({ success: false, message: 'Respuesta vacía de Fortinet' });
    const json = JSON.parse(data);
    if(!json.result) return res.json({ success: false, message: 'Sin resultado de Fortinet' });
    const result = { success: true, path: json.result.path || [], available_from_extended: json.result.available_from_extended || [] };
    if(result.path.length > 0) {
      _fortinetCache[cacheKey] = result;
      try { saveJSON(FORTINET_CACHE_FILE, _fortinetCache); } catch(e) {}
    }
    res.json(result);
  } catch(e) {
    res.json({ success: false, message: e.message });
  }
});

// ── FORTINET FIRMWARE ────────────────────────────────────────────────────────
const fortinetUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const model = sanitizeModelStrict(req.params.model);
      if (!model) return cb(new Error('Nombre de modelo invalido'));
      let dir = path.join(__dirname, 'public', 'fortinet', model);
      const sub = req.query.sub ? sanitizeModelStrict(req.query.sub) : null;
      if (req.query.sub && !sub) return cb(new Error('Nombre de subcarpeta invalido'));
      if (sub) dir = path.join(dir, sub);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      req._fortinetDestDir = dir;
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const dir = req._fortinetDestDir;
      const ver = req.query.ver ? String(req.query.ver).trim() : '';
      const verValida = /^\d+\.\d+\.\d+$/.test(ver);
      const overwrite = req.query.overwrite === '1';
      let name = file.originalname;
      if (verValida && !name.includes(ver)) {
        const ext = path.extname(name);
        const base = name.slice(0, name.length - ext.length);
        name = base + '_' + ver + ext;
      }
      if (dir && fs.existsSync(path.join(dir, name))) {
        if (overwrite) {
          try { fs.unlinkSync(path.join(dir, name)); } catch (e) { return cb(new Error('No se pudo sobrescribir el archivo existente: ' + e.message)); }
        } else {
          return cb(new Error('Ya existe un archivo con ese nombre: ' + name));
        }
      }
      if (dir && verValida && !overwrite) {
        const existentes = fs.readdirSync(dir).filter(f => f.includes('_' + ver + '.') || f.includes('v' + ver + '.') || f.includes('v' + ver + '-'));
        if (existentes.length) {
          return cb(new Error('Ya existe firmware con la version ' + ver + ': ' + existentes.join(', ')));
        }
      }
      cb(null, name);
    }
  }),
  limits: { fileSize: 500 * 1024 * 1024 }
});

app.post('/api/fortinet/upload/:model', requireAdmin, (req, res, next) => {
  if (!sanitizeModelStrict(req.params.model)) return res.json({ success: false, message: 'Nombre de modelo invalido: solo letras, numeros, guion y guion bajo' });
  fortinetUpload.single('file')(req, res, (err) => {
    if (err) return res.json({ success: false, message: err.message });
    if (!req.file) return res.json({ success: false, message: 'No se recibió archivo' });
    logAudit(req, 'FORTINET_FIRMWARE_SUBIR', 'Modelo: ' + req.params.model + ', Archivo: ' + req.file.originalname);
    res.json({ success: true, filename: req.file.originalname });
  });
});

app.delete('/api/fortinet/:model/:filename', requireAdmin, (req, res) => {
  const model = sanitizeModelStrict(req.params.model);
  if (!model) return res.json({ success: false, message: 'Nombre de modelo invalido' });
  const modelDir = path.join(__dirname, 'public', 'fortinet', model);
  const relPath = req.params.filename;
  const filePath = path.normalize(path.join(modelDir, relPath));
  if (filePath !== modelDir && !filePath.startsWith(modelDir + path.sep)) {
    return res.json({ success: false, message: 'Ruta invalida' });
  }
  if (!fs.existsSync(filePath)) return res.json({ success: false, message: 'Archivo no encontrado' });
  fs.unlinkSync(filePath);
  logAudit(req, 'FORTINET_FIRMWARE_ELIMINAR', 'Modelo: ' + req.params.model + ', Archivo: ' + req.params.filename);
  res.json({ success: true });
});

app.get('/api/fortinet/list', requireAuth, (req, res) => {
  const base = path.join(__dirname, 'public', 'fortinet');
  if (!fs.existsSync(base)) return res.json([]);
  const getAllFiles = (dir, prefix) => {
    const entries = fs.readdirSync(dir);
    let files = [];
    entries.forEach(e => {
      const full = path.join(dir, e);
      const rel = prefix ? prefix+'/'+e : e;
      if (fs.statSync(full).isDirectory()) {
        files = files.concat(getAllFiles(full, rel));
      } else {
        files.push({ file: e, path: rel });
      }
    });
    return files;
  };
  const models = fs.readdirSync(base).filter(f => fs.statSync(path.join(base, f)).isDirectory());
  const result = models.map(model => {
    const files = getAllFiles(path.join(base, model), '');
    return { model, files };
  }).filter(m => m.files.length > 0);
  res.json(result);
});

// ── CISCO IOS ─────────────────────────────────────────────────────────────
const ciscoUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const model = sanitizeModelStrict(req.params.model);
      if (!model) return cb(new Error('Nombre de modelo invalido'));
      let dir = path.join(__dirname, 'public', 'cisco', model);
      const sub = req.query.sub ? sanitizeModelStrict(req.query.sub) : null;
      if (req.query.sub && !sub) return cb(new Error('Nombre de subcarpeta invalido'));
      if (sub) dir = path.join(dir, sub);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      req._ciscoDestDir = dir;
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const dir = req._ciscoDestDir;
      const name = file.originalname;
      if (dir && fs.existsSync(path.join(dir, name))) {
        return cb(new Error('Ya existe un archivo con ese nombre: ' + name));
      }
      cb(null, name);
    }
  }),
  limits: { fileSize: 2048 * 1024 * 1024 }
});

app.post('/api/cisco/upload/:model', requireAdmin, (req, res, next) => {
  if (!sanitizeModelStrict(req.params.model)) return res.json({ success: false, message: 'Nombre de modelo invalido: solo letras, numeros, guion y guion bajo' });
  ciscoUpload.single('file')(req, res, (err) => {
    if (err) return res.json({ success: false, message: err.message });
    if (!req.file) return res.json({ success: false, message: 'No se recibi\u00f3 archivo' });
    logAudit(req, 'CISCO_IOS_SUBIR', 'Modelo: ' + req.params.model + ', Archivo: ' + req.file.originalname);
    res.json({ success: true, filename: req.file.originalname });
  });
});

app.delete('/api/cisco/:model/:filename', requireAdmin, (req, res) => {
  const model = sanitizeModelStrict(req.params.model);
  if (!model) return res.json({ success: false, message: 'Nombre de modelo invalido' });
  const filename = path.basename(req.params.filename);
  const filePath = path.join(__dirname, 'public', 'cisco', model, filename);
  if (!fs.existsSync(filePath)) return res.json({ success: false, message: 'Archivo no encontrado' });
  fs.unlinkSync(filePath);
  logAudit(req, 'CISCO_IOS_ELIMINAR', 'Modelo: ' + req.params.model + ', Archivo: ' + req.params.filename);
  res.json({ success: true });
});

app.get('/api/cisco/list', requireAuth, (req, res) => {
  const base = path.join(__dirname, 'public', 'cisco');
  if (!fs.existsSync(base)) return res.json([]);
  const getAllFiles = (dir, prefix) => {
    const entries = fs.readdirSync(dir);
    let files = [];
    entries.forEach(e => {
      const full = path.join(dir, e);
      const rel = prefix ? prefix+'/'+e : e;
      if (fs.statSync(full).isDirectory()) {
        files = files.concat(getAllFiles(full, rel));
      } else {
        files.push({ file: e, path: rel });
      }
    });
    return files;
  };
  const models = fs.readdirSync(base).filter(f => fs.statSync(path.join(base, f)).isDirectory());
  const result = models.map(model => {
    const files = getAllFiles(path.join(base, model), '');
    return { model, files };
  }).filter(m => m.files.length > 0);
  res.json(result);
});

// ── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  try {
    const ms = fs.existsSync(MULTISHEET_FILE) ? fs.statSync(MULTISHEET_FILE) : null;
    const users = fs.existsSync(USERS_FILE) ? fs.statSync(USERS_FILE) : null;
    const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    res.json({
      status: 'ok',
      uptime: Math.round(process.uptime()) + 's',
      memoria_mb: memMB,
      archivos: {
        multisheet: ms ? { size_kb: Math.round(ms.size/1024), modificado: ms.mtime } : null,
        users: users ? { size_kb: Math.round(users.size/1024), modificado: users.mtime } : null
      },
      timestamp: new Date().toISOString()
    });
  } catch(e) {
    res.status(500).json({ status: 'error', message: e.message });
  }
});


// ── FTP ───────────────────────────────────────────────────────────────────────
const FtpClient = require('ftp');

function ftpConnect() {
  return new Promise((resolve, reject) => {
    const c = new FtpClient();
    c.on('ready', () => resolve(c));
    c.on('error', reject);
    c.connect({
      host: process.env.FTP_HOST,
      port: parseInt(process.env.FTP_PORT) || 21,
      user: process.env.FTP_USER,
      password: process.env.FTP_PASS,
      connTimeout: 10000,
      pasvTimeout: 10000
    });
  });
}

// Listar directorio FTP
app.get('/api/ftp/list', requireAdmin, async (req, res) => {
  const dir = req.query.dir || '/';
  let c;
  try {
    c = await ftpConnect();
    const files = await new Promise((resolve, reject) => {
      c.list(dir, (err, list) => {
        if (err) reject(err);
        else resolve(list);
      });
    });
    c.end();
    res.json({ success: true, dir, files: files.map(f => ({
      name: f.name,
      type: f.type === 'd' ? 'dir' : 'file',
      size: f.size,
      date: f.date
    }))});
  } catch(e) {
    if(c) try { c.end(); } catch(_) {}
    res.json({ success: false, message: e.message });
  }
});

// Descargar archivo del FTP
app.get('/api/ftp/download', requireAdmin, async (req, res) => {
  const filepath = req.query.path;
  if (!filepath) return res.status(400).json({ error: 'Falta path' });
  const filename = path.basename(filepath);
  let c;
  try {
    c = await ftpConnect();
    const stream = await new Promise((resolve, reject) => {
      c.get(filepath, (err, stream) => {
        if (err) reject(err);
        else resolve(stream);
      });
    });
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.setHeader('Content-Type', 'application/octet-stream');
    stream.once('close', () => { c.end(); });
    stream.pipe(res);
  } catch(e) {
    if(c) try { c.end(); } catch(_) {}
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});


// ── AGENDA ───────────────────────────────────────────────────────────────────


app.delete('/api/agenda-config/:key', requireSuperAdmin, (req, res) => {
  const config = loadJSON(AGENDA_CONFIG_FILE) || {};
  const key = req.params.key;
  if (!config[key]) return res.json({ success: false, message: 'Pestaña no encontrada' });
  const sheetName = config[key].sheet;
  logAudit(req, 'AGENDA_ELIMINAR_PESTANA', 'Label: ' + config[key].label);
  delete config[key];
  saveJSON(AGENDA_CONFIG_FILE, config);
  res.json({ success: true });
});


// ── MONITOREO ─────────────────────────────────────────────────────────────────
// Verificar si alguna red de gestion VPN es alcanzable via Lenovo
app.get('/api/monitoreo/vpn-status', requireAuth, (req, res) => {
  const { exec } = require('child_process');

  // Un destino representativo por cada segmento VPN
  const destinos = [
    '10.156.0.1',
    '10.158.0.1',
    '172.16.10.30'
  ];

  let pendientes = destinos.length;
  let activa = false;

  destinos.forEach(ip => {
    exec(`ping -c 1 -W 2 ${ip}`, (err, stdout) => {
      if (!err && stdout.includes('1 received')) {
        activa = true;
      }

      pendientes--;

      if (pendientes === 0) {
        res.json({ activa });
      }
    });
  });
});

// Obtener equipos de BD_Equipos para monitorear
app.get('/api/monitoreo/equipos', requireAuth, (req, res) => {
  try {
    const ms = loadJSON(MULTISHEET_FILE) || {};
    const servicios = ms['BD_Servicios'] || [];
    const q = (req.query.q || '').trim().toUpperCase();
    const resultado = servicios
      .filter(e => e.Ip_Gestion && e.Ip_Gestion.trim())
      .filter(e => !q || 
        (e.Cliente||'').toUpperCase().includes(q) ||
        (e.Ip_Gestion||'').includes(q) ||
        (e.Codigo_Servicio||'').toUpperCase().includes(q) ||
        (e.Comuna||'').toUpperCase().includes(q)
      )
      .slice(0, 200)
      .map(e => ({
        nombre: e.Cliente || '',
        codigo: e.Codigo_Servicio || '',
        ip: e.Ip_Gestion.trim(),
        direccion: e.Direccion || '',
        comuna: e.Comuna || ''
      }));
    res.json(resultado);
  } catch(e) { res.json([]); }
});

// ── MANEJO DE ERRORES DE MULTER (evita páginas HTML de error en la API) ─────
app.use((err, req, res, next) => {
  if (err && err.name === 'MulterError') {
    return res.status(400).json({ success: false, error: err.message });
  }
  if (err) {
    console.error('[Error no manejado]', err.message);
    return res.status(500).json({ success: false, error: 'Error interno del servidor' });
  }
  next();
});


// --- PROTECCION /api/folders: login admin + nombres validos + auditoria ---
const FOLDER_MODULOS = ['fortinet', 'cisco', 'kmz'];
const FOLDER_SEGMENTO = /^[A-Za-z0-9_-][A-Za-z0-9_.-]*$/;
function folderSegmentoValido(s) {
  return typeof s === 'string' && s.length > 0 && s.length <= 100 && FOLDER_SEGMENTO.test(s);
}
app.use('/api/folders', requireAdmin, (req, res, next) => {
  const esGet = req.method === 'GET';
  const datos = esGet ? req.query : (req.body || {});
  const fallo = (msg) => res.status(400).json({ success: false, message: msg, folders: [] });
  if (!FOLDER_MODULOS.includes(datos.module)) return fallo('Modulo invalido');
  const sub = esGet ? datos.path : datos.targetPath;
  if (sub !== undefined && sub !== '') {
    if (typeof sub !== 'string') return fallo('Ruta invalida');
    const partes = sub.split('/').filter(Boolean);
    if (!partes.every(folderSegmentoValido)) return fallo('Ruta invalida');
  }
  for (const campo of ['folderName', 'oldName', 'newName']) {
    if (datos[campo] !== undefined && !folderSegmentoValido(datos[campo])) {
      return fallo('Nombre de carpeta invalido: solo letras, numeros, punto, guion y guion bajo');
    }
  }
  if (!esGet) {
    const nombre = datos.folderName || datos.oldName || '';
    const detalle = datos.module + '/' + (datos.targetPath || '') + ' ' + nombre + (datos.newName ? ' -> ' + datos.newName : '');
    logAudit(req, 'CARPETA_' + req.path.replace(/\W/g, '').toUpperCase(), detalle.slice(0, 300));
  }
  next();
});

// --- GESTIÓN AVANZADA DE CARPETAS (RENAME/DELETE) ---
app.post('/api/folders/rename', (req, res) => {
    try {
        const { module: mod, targetPath, oldName, newName } = req.body;
        if (!mod || !oldName || !newName) {
            return res.json({ success: false, message: 'Faltan datos requeridos' });
        }
        const cleanNew = newName.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
        let baseDir = '';
        if (mod === 'fortinet') baseDir = path.join(__dirname, 'public', 'fortinet');
        else if (mod === 'cisco') baseDir = path.join(__dirname, 'public', 'cisco');
        else if (mod === 'kmz') baseDir = path.join(__dirname, 'uploads', 'kmz');
        else return res.json({ success: false, message: 'Módulo inválido' });

        const oldTarget = targetPath ? path.join(baseDir, targetPath, oldName) : path.join(baseDir, oldName);
        const newTarget = targetPath ? path.join(baseDir, targetPath, cleanNew) : path.join(baseDir, cleanNew);
        
        const resolvedBase = path.resolve(baseDir);
        if (!path.resolve(oldTarget).startsWith(resolvedBase) || !path.resolve(newTarget).startsWith(resolvedBase)) {
            return res.json({ success: false, message: 'Ruta no permitida' });
        }

        if (!fs.existsSync(oldTarget)) {
            return res.json({ success: false, message: 'La carpeta de origen no existe' });
        }

        fs.renameSync(oldTarget, newTarget);
        return res.json({ success: true, message: 'Carpeta renombrada exitosamente' });
    } catch (err) {
        console.error('Error al renombrar carpeta:', err);
        return res.json({ success: false, message: 'Error interno al renombrar la carpeta' });
    }
});

app.post('/api/folders/delete', (req, res) => {
    try {
        const { module: mod, targetPath, folderName } = req.body;
        if (!mod || !folderName) {
            return res.json({ success: false, message: 'Faltan datos requeridos' });
        }
        let baseDir = '';
        if (mod === 'fortinet') baseDir = path.join(__dirname, 'public', 'fortinet');
        else if (mod === 'cisco') baseDir = path.join(__dirname, 'public', 'cisco');
        else if (mod === 'kmz') baseDir = path.join(__dirname, 'uploads', 'kmz');
        else return res.json({ success: false, message: 'Módulo inválido' });

        const fullTarget = targetPath ? path.join(baseDir, targetPath, folderName) : path.join(baseDir, folderName);
        const resolvedBase = path.resolve(baseDir);
        const resolvedTarget = path.resolve(fullTarget);

        if (!resolvedTarget.startsWith(resolvedBase)) {
            return res.json({ success: false, message: 'Ruta no permitida' });
        }

        if (!fs.existsSync(resolvedTarget)) {
            return res.json({ success: false, message: 'La carpeta no existe' });
        }

        fs.rmSync(resolvedTarget, { recursive: true, force: true });
        return res.json({ success: true, message: 'Carpeta eliminada exitosamente' });
    } catch (err) {
        console.error('Error al eliminar carpeta:', err);
        return res.json({ success: false, message: 'Error interno al eliminar la carpeta' });
    }
});


// --- GESTIÓN DE CARPETAS API ---
app.get('/api/folders/list', (req, res) => {
    try {
        const { module: mod, path: subpath } = req.query;
        let baseDir = '';
        if (mod === 'fortinet') baseDir = path.join(__dirname, 'public', 'fortinet');
        else if (mod === 'cisco') baseDir = path.join(__dirname, 'public', 'cisco');
        else if (mod === 'kmz') baseDir = path.join(__dirname, 'uploads', 'kmz');
        else return res.json({ success: false, message: 'Módulo inválido', folders: [] });

        const targetDir = subpath ? path.join(baseDir, subpath) : baseDir;
        const resolvedBase = path.resolve(baseDir);
        const resolvedTarget = path.resolve(targetDir);

        if (!resolvedTarget.startsWith(resolvedBase) || !fs.existsSync(resolvedTarget)) {
            return res.json({ success: true, folders: [] });
        }

        const items = fs.readdirSync(resolvedTarget, { withFileTypes: true });
        const folders = items.filter(item => item.isDirectory()).map(item => item.name);
        return res.json({ success: true, folders });
    } catch (err) {
        console.error('Error al listar carpetas:', err);
        return res.json({ success: false, message: 'Error interno', folders: [] });
    }
});

app.post('/api/folders/create', (req, res) => {
    try {
        const { module: mod, targetPath, folderName } = req.body;
        if (!mod || !folderName) {
            return res.json({ success: false, message: 'Faltan datos requeridos' });
        }
        const cleanName = folderName.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
        let baseDir = '';
        if (mod === 'fortinet') baseDir = path.join(__dirname, 'public', 'fortinet');
        else if (mod === 'cisco') baseDir = path.join(__dirname, 'public', 'cisco');
        else if (mod === 'kmz') baseDir = path.join(__dirname, 'uploads', 'kmz');
        else return res.json({ success: false, message: 'Módulo inválido' });

        const parentDir = targetPath ? path.join(baseDir, targetPath) : baseDir;
        const newFolderDir = path.join(parentDir, cleanName);

        const resolvedBase = path.resolve(baseDir);
        if (!path.resolve(newFolderDir).startsWith(resolvedBase)) {
            return res.json({ success: false, message: 'Ruta no permitida' });
        }

        if (!fs.existsSync(parentDir)) {
            fs.mkdirSync(parentDir, { recursive: true });
        }

        if (!fs.existsSync(newFolderDir)) {
            fs.mkdirSync(newFolderDir, { recursive: true });
        }

        return res.json({ success: true, message: 'Carpeta creada exitosamente' });
    } catch (err) {
        console.error('Error al crear carpeta:', err);
        return res.json({ success: false, message: 'Error interno al crear carpeta' });
    }
});

app.post('/api/folders/rename', (req, res) => {
    try {
        const { module: mod, targetPath, oldName, newName } = req.body;
        if (!mod || !oldName || !newName) {
            return res.json({ success: false, message: 'Faltan datos requeridos' });
        }
        const cleanNew = newName.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
        let baseDir = '';
        if (mod === 'fortinet') baseDir = path.join(__dirname, 'public', 'fortinet');
        else if (mod === 'cisco') baseDir = path.join(__dirname, 'public', 'cisco');
        else if (mod === 'kmz') baseDir = path.join(__dirname, 'uploads', 'kmz');
        else return res.json({ success: false, message: 'Módulo inválido' });

        const oldTarget = targetPath ? path.join(baseDir, targetPath, oldName) : path.join(baseDir, oldName);
        const newTarget = targetPath ? path.join(baseDir, targetPath, cleanNew) : path.join(baseDir, cleanNew);
        
        const resolvedBase = path.resolve(baseDir);
        if (!path.resolve(oldTarget).startsWith(resolvedBase) || !path.resolve(newTarget).startsWith(resolvedBase)) {
            return res.json({ success: false, message: 'Ruta no permitida' });
        }

        if (!fs.existsSync(oldTarget)) {
            return res.json({ success: false, message: 'La carpeta de origen no existe' });
        }

        fs.renameSync(oldTarget, newTarget);
        return res.json({ success: true, message: 'Carpeta renombrada exitosamente' });
    } catch (err) {
        console.error('Error al renombrar carpeta:', err);
        return res.json({ success: false, message: 'Error interno al renombrar la carpeta' });
    }
});

app.post('/api/folders/delete', (req, res) => {
    try {
        const { module: mod, targetPath, folderName } = req.body;
        if (!mod || !folderName) {
            return res.json({ success: false, message: 'Faltan datos requeridos' });
        }
        let baseDir = '';
        if (mod === 'fortinet') baseDir = path.join(__dirname, 'public', 'fortinet');
        else if (mod === 'cisco') baseDir = path.join(__dirname, 'public', 'cisco');
        else if (mod === 'kmz') baseDir = path.join(__dirname, 'uploads', 'kmz');
        else return res.json({ success: false, message: 'Módulo inválido' });

        const fullTarget = targetPath ? path.join(baseDir, targetPath, folderName) : path.join(baseDir, folderName);
        const resolvedBase = path.resolve(baseDir);
        const resolvedTarget = path.resolve(fullTarget);

        if (!resolvedTarget.startsWith(resolvedBase)) {
            return res.json({ success: false, message: 'Ruta no permitida' });
        }

        if (!fs.existsSync(resolvedTarget)) {
            return res.json({ success: false, message: 'La carpeta no existe' });
        }

        fs.rmSync(resolvedTarget, { recursive: true, force: true });
        return res.json({ success: true, message: 'Carpeta eliminada exitosamente' });
    } catch (err) {
        console.error('Error al eliminar carpeta:', err);
        return res.json({ success: false, message: 'Error interno al eliminar la carpeta' });
    }
});

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.listen(PORT, () => { console.log('NetQuery corriendo en http://localhost:' + PORT); });

// ── BACKUP AUTOMÁTICO SEMANAL BD (Domingo 23:59) ──
function msHasta(hora, minuto, diaSemana = null, diaMes = null) {
  const ahora = new Date();
  const objetivo = new Date(ahora);
  if (diaSemana !== null) {
    // Próximo día de la semana (0=Dom, 1=Lun, ... 6=Sab)
    let diff = diaSemana - ahora.getDay();
    if (diff <= 0) diff += 7;
    objetivo.setDate(ahora.getDate() + diff);
  } else if (diaMes !== null) {
    // Próximo día del mes
    objetivo.setDate(diaMes);
    if (objetivo <= ahora) objetivo.setMonth(objetivo.getMonth() + 1);
  }
  objetivo.setHours(hora, minuto, 0, 0);
  return objetivo - ahora;
}

async function ejecutarBackupBD() {
  try {
    const multisheet = loadJSON(MULTISHEET_FILE);
    const ts = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
    const filename = 'backup-' + ts + '.xlsx';
    const xlsxFile = path.join(BACKUP_DIR, filename);
    const workbook = new ExcelJS.Workbook();
    let totalRows = 0;
    for (const [sheetName, data] of Object.entries(multisheet)) {
      if (!Array.isArray(data) || data.length === 0) continue;
      const worksheet = workbook.addWorksheet(sheetName);
      const columns = Object.keys(data[0]);
      worksheet.columns = columns.map(col => ({ header: col, key: col, width: 22 }));
      data.forEach(row => worksheet.addRow(row));
      totalRows += data.length;
    }
    await workbook.xlsx.writeFile(xlsxFile);
    console.log(`[Backup BD] Backup creado: ${filename} (${totalRows} registros)`);
  } catch(e) {
    console.error('[Backup BD] Error en backup:', e.message);
    sendAlert('Error en backup automatico', 'El backup semanal fallo: <strong>' + e.message + '</strong>');
  }
}

function limpiarBackupAntiguo() {
  try {
    const archivos = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('backup-') && f.endsWith('.xlsx'))
      .sort(); // orden ascendente = más antiguo primero
    if (archivos.length > 0) {
      const masAntiguo = archivos[0];
      fs.unlinkSync(path.join(BACKUP_DIR, masAntiguo));
      console.log(`[Backup BD] Backup eliminado (más antiguo): ${masAntiguo}`);
    } else {
      console.log('[Backup BD] No hay backups para eliminar');
    }
  } catch(e) {
    console.error('[Backup BD] Error limpieza:', e.message);
  }
}

// ── ROTACIÓN AUTOMÁTICA DE AUDIT ─────────────────────────────────────────────
function rotarAudit() {
  try {
    const _rawLogs = loadJSON(AUDIT_FILE); const logs = Array.isArray(_rawLogs) ? _rawLogs : [];
    if (logs.length > 2000) {
      const nuevos = logs.slice(-1000);
      saveJSON(AUDIT_FILE, nuevos);
      console.log('[Audit] Rotación: ' + logs.length + ' → ' + nuevos.length + ' registros');
    }
  } catch(e) { console.error('[Audit] Error rotación:', e.message); }
}
// Rotar audit cada día a las 03:00
setInterval(() => {
  const h = new Date().getHours(), m = new Date().getMinutes();
  if(h === 3 && m === 0) rotarAudit();
}, 60 * 1000);

// -- BACKUP AUTOMATICO IPDB: cada 24 h, conserva los ultimos 14 --
function edadUltimoBackupIPDBHoras() {
  try {
    const tiempos = fs.readdirSync(IP_BACKUP_DIR)
      .filter(f => f.startsWith('ipdb-backup-') && f.endsWith('.xlsx'))
      .map(f => fs.statSync(path.join(IP_BACKUP_DIR, f)).mtimeMs);
    if (!tiempos.length) return Infinity;
    return (Date.now() - Math.max(...tiempos)) / 3600000;
  } catch (e) { return Infinity; }
}

async function ejecutarBackupIPDB() {
  try {
    const db = loadJSON(IP_FILE) || [];
    if (!fs.existsSync(IP_BACKUP_DIR)) fs.mkdirSync(IP_BACKUP_DIR, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = 'ipdb-backup-' + ts + '.xlsx';
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('IPdb');
    if (db.length > 0) {
      const cols = Object.keys(db[0]);
      worksheet.columns = cols.map(c => ({ header: c, key: c, width: 20 }));
      db.forEach(row => worksheet.addRow(row));
    }
    await workbook.xlsx.writeFile(path.join(IP_BACKUP_DIR, filename));
    const files = fs.readdirSync(IP_BACKUP_DIR)
      .filter(f => f.startsWith('ipdb-backup-') && f.endsWith('.xlsx'))
      .sort();
    if (files.length > 14) {
      files.slice(0, files.length - 14).forEach(f => fs.unlinkSync(path.join(IP_BACKUP_DIR, f)));
    }
    console.log('[Backup IPDB] Backup creado: ' + filename + ' (' + db.length + ' registros)');
  } catch (e) {
    console.error('[Backup IPDB] Error en backup:', e.message);
    sendAlert('Error en backup automatico de IPDB', 'El backup de IPDB fallo: <strong>' + e.message + '</strong>');
  }
}

function programarBackupBD() {
  // Polling cada minuto: evita setTimeout con valores > 2147483647ms (limite 32-bit Node.js)
  let backupEjecutado = false;
  let limpiezaEjecutada = false;
  let ipdbUltimoIntento = 0;
  console.log("[Backup BD] Scheduler iniciado (polling cada minuto)");
  setInterval(() => {
    const ahora = new Date();
    const dia = ahora.getDay();
    const hora = ahora.getHours();
    const min = ahora.getMinutes();
    const diaMes = ahora.getDate();
    if(dia===0 && hora===23 && min===59) {
      if(!backupEjecutado) { ejecutarBackupBD(); backupEjecutado=true; }
    } else { backupEjecutado=false; }
    if(diaMes===1 && hora===0 && min===0) {
      if(!limpiezaEjecutada) { limpiarBackupAntiguo(); limpiezaEjecutada=true; }
    } else { limpiezaEjecutada=false; }
    // IPDB: si el ultimo backup tiene 24 h o mas, crear uno (maximo un intento por hora)
    if (Date.now() - ipdbUltimoIntento > 3600000 && edadUltimoBackupIPDBHoras() >= 24) {
      ipdbUltimoIntento = Date.now();
      ejecutarBackupIPDB();
    }
  }, 60 * 1000);
}

programarBackupBD();
