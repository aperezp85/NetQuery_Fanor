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
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: 'https://172.17.35.109', credentials: true }));
const PORT = process.env.PORT || 3000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ store: new FileStore({ path: './sessions', ttl: 1800 }), secret: process.env.SESSION_SECRET, resave: true, saveUninitialized: false, rolling: true, cookie: { secure: true, httpOnly: true, sameSite: 'lax', maxAge: 1800000 } }));
const USERS_FILE = './data/users.json';
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
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { success: false, message: 'Demasiados intentos, espera 15 minutos' } });
app.post('/api/login', loginLimiter, (req, res) => { const { username, password } = req.body; if (!username || !password || !isValidUsername(username)) { logAudit(req, 'LOGIN_FALLIDO', 'Formato invalido: ' + sanitizeText(String(username||''), 60)); return res.json({ success: false, message: 'Usuario o contrasena incorrectos' }); } const users = loadJSON(USERS_FILE); const idx = users.findIndex(u => u.username === username && u.activo); if (idx === -1 || !bcrypt.compareSync(password, users[idx].passwordHash)) { logAudit(req, 'LOGIN_FALLIDO', 'Usuario: ' + username); const _ip = req.headers['x-real-ip'] || req.ip || ''; _loginFallidosPorIP[_ip] = (_loginFallidosPorIP[_ip] || 0) + 1; if (_loginFallidosPorIP[_ip] === 3) { sendAlert('Intentos fallidos de login', 'Se detectaron <strong>3 intentos fallidos</strong> desde IP <strong>' + _ip + '</strong> con usuario <strong>' + username + '</strong>.'); } return res.json({ success: false, message: 'Usuario o contrasena incorrectos' }); } const user = users[idx]; user.lastActivity = new Date().toISOString(); saveJSON(USERS_FILE, users); req.session.user = { id: user.id, username: user.username, role: user.role, nombre: user.nombre, mustChangePassword: !!user.mustChangePassword }; const _ipLogin = req.headers['x-real-ip'] || req.ip || ''; delete _loginFallidosPorIP[_ipLogin]; logAudit(req, 'LOGIN_OK', ''); res.json({ success: true, user: req.session.user }); });
app.post('/api/logout', (req, res) => { logAudit(req, 'LOGOUT', ''); req.session.destroy(() => res.json({ success: true })); });
app.get('/api/me', requireAuth, (req, res) => { res.json(req.session.user); });
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
    const logs = loadJSON(AUDIT_FILE) || [];
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
app.get('/api/auditoria', requireSuperAdmin, (req, res) => {
  const logs = loadJSON(AUDIT_FILE) || [];
  res.json(logs.slice().reverse().slice(0, 1000));
});

app.get('/api/sugerencias', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim().toUpperCase();
  if (q.length < 2) return res.json([]);
  const ms = loadJSON(MULTISHEET_FILE) || {};
  const sugerencias = [];
  Object.entries(ms).forEach(([sheet, rows]) => {
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
app.get('/api/consulta/:codigo', requireAuth, (req, res) => {
  const codigo = req.params.codigo.trim().toUpperCase();
  const ms = loadJSON(MULTISHEET_FILE) || {};
  const results = {};
  Object.entries(ms).forEach(([sheet, rows]) => {
    const found = rows.filter(row => {
      // Buscar en CUALQUIER columna que contenga 'codigo' en su nombre
      return Object.entries(row).some(([k, v]) => {
        if (!k.toLowerCase().includes('codigo') && !k.toLowerCase().includes('cod_')) return false;
        const val = (v || '').toString().trim().toUpperCase();
        return val === codigo || val.includes(codigo);
      });
    });
    if (found.length > 0) results[sheet] = found;
  });
  if (Object.keys(results).length === 0) return res.json({ found: false });
  res.json({ found: true, data: results });
});
app.post('/api/datos', requireAdmin, (req, res) => { const db = loadJSON(DB_FILE); const nuevo = sanitizeObject(req.body, 500); if (!nuevo.CODIGO) return res.json({ success: false, message: 'El campo CODIGO es obligatorio' }); const existe = db.find(r => (r.CODIGO || '').toString().trim().toUpperCase() === nuevo.CODIGO.toString().trim().toUpperCase()); if (existe) return res.json({ success: false, message: 'Ya existe un registro con ese CODIGO' }); db.push(nuevo); saveJSON(DB_FILE, db); logAudit(req, 'DATOS_CREAR', 'CODIGO: ' + nuevo.CODIGO); res.json({ success: true }); });
app.put('/api/datos/:codigo', requireAdmin, (req, res) => { const db = loadJSON(DB_FILE); const codigo = sanitizeText(req.params.codigo, 100).trim().toUpperCase(); const cambios = sanitizeObject(req.body, 500); let updated = 0; const newDb = db.map(row => { if ((row.CODIGO || '').toString().trim().toUpperCase() === codigo) { updated++; return { ...row, ...cambios }; } return row; }); if (updated === 0) return res.json({ success: false, message: 'Registro no encontrado' }); saveJSON(DB_FILE, newDb); logAudit(req, 'DATOS_EDITAR', 'CODIGO: ' + codigo); res.json({ success: true, updated }); });
app.delete('/api/datos/:codigo', requireAdmin, (req, res) => { const db = loadJSON(DB_FILE); const codigo = sanitizeText(req.params.codigo, 100).trim().toUpperCase(); const newDb = db.filter(row => (row.CODIGO || '').toString().trim().toUpperCase() !== codigo); if (newDb.length === db.length) return res.json({ success: false, message: 'Registro no encontrado' }); saveJSON(DB_FILE, newDb); logAudit(req, 'DATOS_ELIMINAR', 'CODIGO: ' + codigo); res.json({ success: true }); });
app.get('/api/usuarios', requireSuperAdmin, (req, res) => { const users = loadJSON(USERS_FILE).map(u => ({ ...u, password: undefined, passwordHash: undefined })); res.json(users); });
app.post('/api/usuarios', requireSuperAdmin, (req, res) => { const username = sanitizeText(req.body.username, 60); const password = sanitizeText(req.body.password, 200); const nombre = sanitizeText(req.body.nombre, 100); const role = req.body.role; const temporal = req.body.temporal; if (!username || !password || !nombre || !role) return res.json({ success: false, message: 'Todos los campos son requeridos' }); if (!isValidUsername(username)) return res.json({ success: false, message: 'Usuario invalido: solo letras, numeros, punto y guion (3-60 caracteres)' }); if (password.length < 6) return res.json({ success: false, message: 'La contrasena debe tener minimo 6 caracteres' }); const users = loadJSON(USERS_FILE); if (users.find(u => u.username === username)) return res.json({ success: false, message: 'El usuario ya existe' }); users.push({ id: Date.now(), username, nombre, passwordHash: bcrypt.hashSync(password, 10), role: role === 'admin' ? 'admin' : 'consulta', activo: true, mustChangePassword: !!temporal }); saveJSON(USERS_FILE, users); logAudit(req, 'USUARIO_CREAR', 'Usuario: ' + username + ' (' + role + ')'); res.json({ success: true }); });
app.put('/api/usuarios/:id', requireSuperAdmin, (req, res) => { const users = loadJSON(USERS_FILE); const idx = users.findIndex(u => u.id == req.params.id); if (idx === -1) return res.json({ success: false, message: 'Usuario no encontrado' }); const nombre = sanitizeText(req.body.nombre, 100); const role = req.body.role; const activo = req.body.activo; const password = sanitizeText(req.body.password, 200); const temporal = req.body.temporal; if (password && password.length < 6) return res.json({ success: false, message: 'La contrasena debe tener minimo 6 caracteres' }); if (nombre) users[idx].nombre = nombre; if (role) users[idx].role = role; if (activo !== undefined) users[idx].activo = activo; if (password) { users[idx].passwordHash = bcrypt.hashSync(password, 10); users[idx].mustChangePassword = !!temporal; } saveJSON(USERS_FILE, users); logAudit(req, 'USUARIO_EDITAR', 'Usuario: ' + users[idx].username); res.json({ success: true }); });
app.delete('/api/usuarios/:id', requireSuperAdmin, (req, res) => { let users = loadJSON(USERS_FILE); const target = users.find(u => u.id == req.params.id); if (target && target.username === 'admin') return res.json({ success: false, message: 'No se puede eliminar el admin principal' }); users = users.filter(u => u.id != req.params.id); saveJSON(USERS_FILE, users); logAudit(req, 'USUARIO_ELIMINAR', target ? ('Usuario: ' + target.username) : ('ID: ' + req.params.id)); res.json({ success: true }); });
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
    const multisheet = {};
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
  sites = sites.filter(s => s.id != req.params.id);
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

app.put('/api/ipdb/:id', requireAdmin, (req, res) => {
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

app.delete('/api/ipdb/:id', requireAdmin, (req, res) => {
  let db = loadJSON(IP_FILE) || [];
  const target = db.find(r => r.id == req.params.id);
  db = db.filter(r => r.id != req.params.id);
  saveJSON(IP_FILE, db);
  logAudit(req, 'IPDB_ELIMINAR', target ? (target.IP || target.Equipo || '') : ('ID: ' + req.params.id));
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
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/ipdb/all', requireAdmin, (req, res) => {
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
app.get('/api/palo/backup/download/:filename', requireAuth, (req, res) => {
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
  logAudit(req, 'MULTISHEET_CREAR', 'Hoja: ' + sheet);
  res.json({ success: true });
});

app.put('/api/multisheet', requireAdmin, (req, res) => {
  const { sheet, keyField, keyValue, data } = req.body;
  const ms = loadJSON(MULTISHEET_FILE) || {};
  if(!ms[sheet]) return res.json({ success: false, message: 'Hoja no encontrada' });
  ms[sheet] = ms[sheet].map(row => {
    if((row[keyField]||'').toString().trim() === keyValue.toString().trim()) return { ...row, ...data };
    return row;
  });
  saveJSON(MULTISHEET_FILE, ms);
  logAudit(req, 'MULTISHEET_EDITAR', 'Hoja: ' + sheet + ', ' + keyField + ': ' + keyValue);
  res.json({ success: true });
});

app.delete('/api/multisheet', requireAdmin, (req, res) => {
  const { sheet, keyField, keyValue } = req.body;
  const ms = loadJSON(MULTISHEET_FILE) || {};
  if(!ms[sheet]) return res.json({ success: false, message: 'Hoja no encontrada' });
  ms[sheet] = ms[sheet].filter(row => (row[keyField]||'').toString().trim() !== keyValue.toString().trim());
  saveJSON(MULTISHEET_FILE, ms);
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

// ── BACKUP GOOGLE DRIVE ──────────────────────────────────────────────────────
app.post('/api/backup/drive', requireSuperAdmin, (req, res) => {
  const { exec } = require('child_process');
  exec('/home/ubuntu/backup_queulat.sh', (error, stdout, stderr) => {
    if (error) return res.json({ success: false, message: stderr || error.message });
    res.json({ success: true, message: stdout.trim() });
  });
});

// ── FORTINET UPGRADE PATH ────────────────────────────────────────────────────
const _fortinetCache = {};
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
    if(result.path.length > 0) _fortinetCache[cacheKey] = result;
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
      const dir = path.join(__dirname, 'public', 'fortinet', model);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, file.originalname)
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
  const filename = path.basename(req.params.filename);
  const filePath = path.join(__dirname, 'public', 'fortinet', model, filename);
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

function programarBackupBD() {
  // Polling cada minuto: evita setTimeout con valores > 2147483647ms (limite 32-bit Node.js)
  let backupEjecutado = false;
  let limpiezaEjecutada = false;
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
  }, 60 * 1000);
}

programarBackupBD();
