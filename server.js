const express = require('express');
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
app.use(session({ store: new FileStore({ path: './sessions', ttl: 86400 }), secret: process.env.SESSION_SECRET || 'netquery_secret_2024', resave: false, saveUninitialized: false, cookie: { secure: true, httpOnly: true, sameSite: 'lax', maxAge: 86400000 } }));
const USERS_FILE = './data/users.json';
const DB_FILE = './data/database.json';
const BACKUP_DIR = './data/backups';
function loadJSON(file) { if (!fs.existsSync(file)) return null; return JSON.parse(fs.readFileSync(file, 'utf8')); }
function saveJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }
if (!fs.existsSync('./data')) fs.mkdirSync('./data', { recursive: true });
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads', { recursive: true });
if (!fs.existsSync('./sessions')) fs.mkdirSync('./sessions', { recursive: true });
if (!fs.existsSync(USERS_FILE)) { const hash = bcrypt.hashSync('Admin1234!', 10); saveJSON(USERS_FILE, [{ id: 1, username: 'admin', password: hash, role: 'admin', nombre: 'Administrador', activo: true, mustChangePassword: false }]); }
if (!fs.existsSync(DB_FILE)) saveJSON(DB_FILE, []);
function requireAuth(req, res, next) { if (!req.session.user) return res.status(401).json({ error: 'No autorizado' }); next(); }
function requireAdmin(req, res, next) { if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Acceso denegado' }); next(); }
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { success: false, message: 'Demasiados intentos, espera 15 minutos' } });
app.post('/api/login', loginLimiter, (req, res) => { const { username, password } = req.body; const users = loadJSON(USERS_FILE); const user = users.find(u => u.username === username && u.activo); if (!user || !bcrypt.compareSync(password, user.passwordHash)) return res.json({ success: false, message: 'Usuario o contrasena incorrectos' }); req.session.user = { id: user.id, username: user.username, role: user.role, nombre: user.nombre, mustChangePassword: !!user.mustChangePassword }; res.json({ success: true, user: req.session.user }); });
app.post('/api/logout', (req, res) => { req.session.destroy(() => res.json({ success: true })); });
app.get('/api/me', requireAuth, (req, res) => { res.json(req.session.user); });
app.post('/api/change-password', requireAuth, (req, res) => { const { newPassword } = req.body; if (!newPassword || newPassword.length < 6) return res.json({ success: false, message: 'Minimo 6 caracteres' }); const users = loadJSON(USERS_FILE); const idx = users.findIndex(u => u.id === req.session.user.id); if (idx === -1) return res.json({ success: false, message: 'Usuario no encontrado' }); users[idx].passwordHash = bcrypt.hashSync(newPassword, 10); users[idx].mustChangePassword = false; saveJSON(USERS_FILE, users); req.session.user.mustChangePassword = false; res.json({ success: true }); });
const MULTISHEET_FILE = './data/multisheet.json';

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
app.post('/api/datos', requireAdmin, (req, res) => { const db = loadJSON(DB_FILE); const nuevo = req.body; if (!nuevo.CODIGO) return res.json({ success: false, message: 'El campo CODIGO es obligatorio' }); const existe = db.find(r => (r.CODIGO || '').toString().trim().toUpperCase() === nuevo.CODIGO.toString().trim().toUpperCase()); if (existe) return res.json({ success: false, message: 'Ya existe un registro con ese CODIGO' }); db.push(nuevo); saveJSON(DB_FILE, db); res.json({ success: true }); });
app.put('/api/datos/:codigo', requireAdmin, (req, res) => { const db = loadJSON(DB_FILE); const codigo = req.params.codigo.trim().toUpperCase(); let updated = 0; const newDb = db.map(row => { if ((row.CODIGO || '').toString().trim().toUpperCase() === codigo) { updated++; return { ...row, ...req.body }; } return row; }); if (updated === 0) return res.json({ success: false, message: 'Registro no encontrado' }); saveJSON(DB_FILE, newDb); res.json({ success: true, updated }); });
app.delete('/api/datos/:codigo', requireAdmin, (req, res) => { const db = loadJSON(DB_FILE); const codigo = req.params.codigo.trim().toUpperCase(); const newDb = db.filter(row => (row.CODIGO || '').toString().trim().toUpperCase() !== codigo); if (newDb.length === db.length) return res.json({ success: false, message: 'Registro no encontrado' }); saveJSON(DB_FILE, newDb); res.json({ success: true }); });
app.get('/api/usuarios', requireAdmin, (req, res) => { const users = loadJSON(USERS_FILE).map(u => ({ ...u, password: undefined })); res.json(users); });
app.post('/api/usuarios', requireAdmin, (req, res) => { const { username, password, nombre, role, temporal } = req.body; if (!username || !password || !nombre || !role) return res.json({ success: false, message: 'Todos los campos son requeridos' }); const users = loadJSON(USERS_FILE); if (users.find(u => u.username === username)) return res.json({ success: false, message: 'El usuario ya existe' }); users.push({ id: Date.now(), username, nombre, passwordHash: bcrypt.hashSync(password, 10), role: role === 'admin' ? 'admin' : 'consulta', activo: true, mustChangePassword: !!temporal }); saveJSON(USERS_FILE, users); res.json({ success: true }); });
app.put('/api/usuarios/:id', requireAdmin, (req, res) => { const users = loadJSON(USERS_FILE); const idx = users.findIndex(u => u.id == req.params.id); if (idx === -1) return res.json({ success: false, message: 'Usuario no encontrado' }); const { nombre, role, activo, password, temporal } = req.body; if (nombre) users[idx].nombre = nombre; if (role) users[idx].role = role; if (activo !== undefined) users[idx].activo = activo; if (password) { users[idx].passwordHash = bcrypt.hashSync(password, 10); users[idx].mustChangePassword = !!temporal; } saveJSON(USERS_FILE, users); res.json({ success: true }); });
app.delete('/api/usuarios/:id', requireAdmin, (req, res) => { let users = loadJSON(USERS_FILE); if (users.find(u => u.id == req.params.id && u.username === 'admin')) return res.json({ success: false, message: 'No se puede eliminar el admin principal' }); users = users.filter(u => u.id != req.params.id); saveJSON(USERS_FILE, users); res.json({ success: true }); });
app.post('/api/usuarios/:id/reset-password', requireAdmin, (req, res) => { const { password } = req.body; if (!password) return res.json({ success: false, message: 'Ingrese una contrasena temporal' }); const users = loadJSON(USERS_FILE); const idx = users.findIndex(u => u.id == req.params.id); if (idx === -1) return res.json({ success: false, message: 'Usuario no encontrado' }); users[idx].passwordHash = bcrypt.hashSync(password, 10); users[idx].mustChangePassword = true; saveJSON(USERS_FILE, users); res.json({ success: true }); });
const storage = multer.diskStorage({ destination: (req, file, cb) => cb(null, './uploads/'), filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)) });
const upload = multer({ storage, fileFilter: (req, file, cb) => { const ext = path.extname(file.originalname).toLowerCase(); if (['.xlsx','.xls','.csv'].includes(ext)) { cb(null, true); } else { cb(new Error('Solo se permiten archivos .xlsx, .xls o .csv')); } }, limits: { fileSize: 50*1024*1024 } });
app.post('/api/upload', requireAdmin, upload.single('file'), async (req, res) => {
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
          if (headers[colNumber-1]) obj[headers[colNumber-1]] = cell.value !== null ? String(cell.value) : '';
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
app.post('/api/db/backup', requireAdmin, async (req, res) => { try { const db = loadJSON(DB_FILE); const ts = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19); const filename = 'backup-' + ts + '.xlsx'; const xlsxFile = path.join(BACKUP_DIR, filename); const workbook = new ExcelJS.Workbook(); const worksheet = workbook.addWorksheet('Datos'); if (db.length > 0) { const columns = Object.keys(db[0]); worksheet.columns = columns.map(col => ({ header: col, key: col, width: 20 })); db.forEach(row => worksheet.addRow(row)); } await workbook.xlsx.writeFile(xlsxFile); res.json({ success: true, file: filename, rows: db.length }); } catch(e) { res.json({ success: false, message: e.message }); } });
app.get('/api/db/backups', requireAdmin, (req, res) => { const files = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.xlsx')).map(f => ({ name: f, size: fs.statSync(path.join(BACKUP_DIR, f)).size })).reverse(); res.json(files); });
app.get('/api/db/backup/download/:filename', requireAdmin, (req, res) => { const filename = path.basename(req.params.filename); const file = path.join(BACKUP_DIR, filename); if (!fs.existsSync(file)) return res.status(404).json({ error: 'No encontrado' }); res.download(file); });
app.delete('/api/db', requireAdmin, (req, res) => { saveJSON(DB_FILE, []); res.json({ success: true }); });

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
  const { nombre, ip } = req.body;
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
    res.json({ success: false, message: e.message });
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
  const nuevo = req.body;
  if (!nuevo.IP && !nuevo.Equipo) return res.json({ success: false, message: 'IP o Equipo requerido' });
  db.push({ id: Date.now(), ...nuevo });
  saveJSON(IP_FILE, db);
  res.json({ success: true });
});

app.put('/api/ipdb/:id', requireAdmin, (req, res) => {
  const db = loadJSON(IP_FILE) || [];
  const idx = db.findIndex(r => r.id == req.params.id);
  if (idx === -1) return res.json({ success: false, message: 'No encontrado' });
  db[idx] = { ...db[idx], ...req.body };
  saveJSON(IP_FILE, db);
  res.json({ success: true });
});

app.delete('/api/ipdb/:id', requireAdmin, (req, res) => {
  let db = loadJSON(IP_FILE) || [];
  db = db.filter(r => r.id != req.params.id);
  saveJSON(IP_FILE, db);
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
  hist[id].push({ avg, loss, estado, hora });
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
  const file = path.join(PALO_BACKUP_DIR, req.params.filename);
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
  res.json({ success: true });
});

app.delete('/api/multisheet', requireAdmin, (req, res) => {
  const { sheet, keyField, keyValue } = req.body;
  const ms = loadJSON(MULTISHEET_FILE) || {};
  if(!ms[sheet]) return res.json({ success: false, message: 'Hoja no encontrada' });
  ms[sheet] = ms[sheet].filter(row => (row[keyField]||'').toString().trim() !== keyValue.toString().trim());
  saveJSON(MULTISHEET_FILE, ms);
  res.json({ success: true });
});

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.listen(PORT, () => { console.log('NetQuery corriendo en http://localhost:' + PORT); });


