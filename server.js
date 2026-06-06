// server.js - Backend para ACE Corporation con Chatbot IA
// npm install express dotenv cors  (SIN IA - sin API key)

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ===== HEADERS DE SEGURIDAD =====
app.use((req, res, next) => {
    // Content-Security-Policy
    res.setHeader('Content-Security-Policy', "default-src 'self' https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; frame-ancestors 'none';");
    
    // X-Frame-Options (protege contra clickjacking)
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Strict-Transport-Security (fuerza HTTPS)
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    
    // X-Content-Type-Options (previene MIME sniffing)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // X-XSS-Protection (extra protección XSS)
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Referrer-Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Permissions-Policy
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    
    next();
});

// ===== DDOS PROTECTION =====
const DDOS_THRESHOLD = 50; // requests
const DDOS_WINDOW = 10000; // 10 segundos
const DDOS_BAN_DURATION = 86400000; // 24 horas

function checkDDoS(ip) {
    if (!ipBehavior.has(ip)) {
        ipBehavior.set(ip, { 
            messageCount: 0, 
            insultos: 0, 
            lastMessage: Date.now(), 
            bloqueado: false,
            requestTimes: [],
            ddosBloqueado: false,
            ddosBannedAt: null
        });
    }
    
    const behavior = ipBehavior.get(ip);
    const now = Date.now();
    
    // Check DDoS ban duration
    if (behavior.ddosBloqueado && now - behavior.ddosBannedAt >= DDOS_BAN_DURATION) {
        behavior.ddosBloqueado = false;
        behavior.requestTimes = [];
        console.log(`✅ IP ${ip} desbloqueada (DDoS ban expirado)`);
    }
    
    if (behavior.ddosBloqueado) {
        return { isDDoS: true, reason: 'IP bloqueada por DDoS' };
    }
    
    // Track request times
    behavior.requestTimes.push(now);
    behavior.requestTimes = behavior.requestTimes.filter(t => now - t < DDOS_WINDOW);
    
    // Detect DDoS pattern
    if (behavior.requestTimes.length > DDOS_THRESHOLD) {
        behavior.ddosBloqueado = true;
        behavior.ddosBannedAt = now;
        console.error(`🔴 DDOS DETECTADO: IP ${ip} (${behavior.requestTimes.length} req en 10s) - BLOQUEADA 24H`);
        return { isDDoS: true, reason: `Demasiadas requests (${behavior.requestTimes.length}/${DDOS_THRESHOLD})` };
    }
    
    return { isDDoS: false };
}

// ===== RATE LIMITING + IP BANNING =====
const ipBehavior = new Map(); // { ip: { messageCount, insultos, lastMessage, bloqueado } }
const MAX_MESSAGES_PER_MINUTE = 10;
const MAX_INSULTS_BEFORE_BAN = 5;
const BAN_DURATION_MS = 3600000; // 1 hora

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
}

function isIPBlocked(ip) {
    const behavior = ipBehavior.get(ip);
    if (!behavior) return false;
    if (behavior.bloqueado && Date.now() - behavior.bannedAt < BAN_DURATION_MS) {
        return true;
    }
    if (behavior.bloqueado && Date.now() - behavior.bannedAt >= BAN_DURATION_MS) {
        behavior.bloqueado = false;
        behavior.insultos = 0;
        behavior.messageCount = 0;
    }
    return false;
}

function updateIPBehavior(ip, messageLength, isInsult) {
    if (!ipBehavior.has(ip)) {
        ipBehavior.set(ip, { messageCount: 0, insultos: 0, lastMessage: Date.now(), bloqueado: false });
    }
    const behavior = ipBehavior.get(ip);
    const now = Date.now();

    // Reset contador cada minuto
    if (now - behavior.lastMessage > 60000) {
        behavior.messageCount = 0;
    }

    behavior.messageCount++;
    behavior.lastMessage = now;

    if (isInsult) {
        behavior.insultos++;
        console.warn(`⚠️ IP ${ip}: insulto #${behavior.insultos}`);
        if (behavior.insultos >= MAX_INSULTS_BEFORE_BAN) {
            behavior.bloqueado = true;
            behavior.bannedAt = now;
            console.error(`🚫 IP ${ip} BLOQUEADA por ${MAX_INSULTS_BEFORE_BAN}+ insultos`);
        }
    }

    return {
        messageCount: behavior.messageCount,
        isRateLimited: behavior.messageCount > MAX_MESSAGES_PER_MINUTE,
        isBlocked: behavior.bloqueado
    };
}

// ===== SISTEMA DE LOGGING (PARA ADMIN DASHBOARD) =====
const systemLogs = {
    events: [],          // Todos los eventos (rolling buffer)
    chatMessages: [],    // Mensajes del chatbot
    stats: {
        totalRequests: 0,
        totalErrors: 0,
        totalDDoS: 0,
        totalMessages: 0,
        totalBlocked: 0,
        totalRateLimited: 0,
        totalInsults: 0,
        totalOutOfScope: 0,
        serverStartTime: Date.now()
    }
};
const MAX_LOG_ENTRIES = 1000;
const geoCache = new Map(); // Cache de geolocalización { ip: { country, city, ... } }

function addLog(type, ip, details) {
    const entry = {
        id: Date.now() + Math.random().toString(36).slice(2, 8),
        type,           // request | error | ddos | block | ratelimit | insult | message | outofscope
        ip,
        details,
        timestamp: new Date().toISOString()
    };
    systemLogs.events.unshift(entry);
    if (systemLogs.events.length > MAX_LOG_ENTRIES) {
        systemLogs.events.pop();
    }
    return entry;
}

async function geolocateIP(ip) {
    // IPs locales no se geolocalizan
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
        return { country: 'Local', city: 'Localhost', isp: 'Local', lat: 0, lon: 0 };
    }
    if (geoCache.has(ip)) {
        return geoCache.get(ip);
    }
    try {
        const cleanIp = ip.replace('::ffff:', '');
        const res = await fetch(`http://ip-api.com/json/${cleanIp}?fields=status,country,countryCode,regionName,city,isp,lat,lon,query`);
        const data = await res.json();
        if (data.status === 'success') {
            const geo = {
                country: data.country,
                countryCode: data.countryCode,
                region: data.regionName,
                city: data.city,
                isp: data.isp,
                lat: data.lat,
                lon: data.lon
            };
            geoCache.set(ip, geo);
            return geo;
        }
    } catch (e) {
        console.error('Error geolocalizando IP:', e.message);
    }
    const unknown = { country: 'Desconocido', city: 'N/A', isp: 'N/A', lat: 0, lon: 0 };
    geoCache.set(ip, unknown);
    return unknown;
}


function normalizeMessage(text) {
    // Reemplazar números por letras comunes (typos)
    const replacements = {
        '0': 'o',
        '1': 'i',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '7': 't',
        '8': 'b',
        '9': 'g'
    };
    let normalized = text.toLowerCase().trim();
    for (const [num, letter] of Object.entries(replacements)) {
        normalized = normalized.replace(new RegExp(num, 'g'), letter);
    }
    // Eliminar espacios múltiples
    normalized = normalized.replace(/\s+/g, ' ');
    return normalized;
}

function detectIntent(text) {
    const normalized = normalizeMessage(text);
    
    const intents = {
        presupuesto: ['presupuesto', 'precio', 'costo', 'cuanto cuesta', 'valor', 'cotiza'],
        servicio: ['servicio', 'pulido', 'plastificado', 'hidrolaqueado', 'parquet', 'reparacion'],
        horario: ['horario', 'hora', 'abierto', 'cierra', 'atienden', 'cuando'],
        ubicacion: ['ubicacion', 'donde', 'direccion', 'localidad', 'encuentran'],
        contacto: ['llamar', 'contactar', 'telefono', 'whatsapp', 'email', 'comunicar']
    };
    
    for (const [intent, keywords] of Object.entries(intents)) {
        if (keywords.some(kw => normalized.includes(kw))) {
            return intent;
        }
    }
    return null;
}

function isOutOfScope(text) {
    const normalized = normalizeMessage(text);
    
    // Palabras clave que indican fuera de scope
    const outOfScopeKeywords = [
        'futbol', 'futbol', 'politica', 'politico', 'chiste', 'broma', 'receta', 'cocina',
        'matematica', 'codigo', 'programar', 'python', 'javascript', 'juego', 'video',
        'musica', 'cancion', 'pelicula', 'cine', 'clima', 'tiempo', 'noticias',
        'bitcoin', 'crypto', 'bolsa', 'acciones', 'amor', 'relacion', 'novio',
        'viaje', 'turismo', 'hotel', 'restaurante', 'comida', 'pizza', 'pizza',
        'medicina', 'doctor', 'enfermedad', 'sintoma', 'covid', 'vacuna',
        'dependencia', 'adiccion', 'droga'
    ];
    
    return outOfScopeKeywords.some(keyword => normalized.includes(keyword));
}

function getOutOfScopeResponse() {
    return "Solo puedo ayudarte con presupuestos, horarios, servicios (Pulido, Plastificado, Hidrolaqueado, Parquet) y ubicación de ACE. ¿Necesitas alguno de estos?";
}

function detectInsult(text) {
    const normalized = normalizeMessage(text);
    const insults = ['idiota', 'tonto', 'boludo', 'pelotudo', 'estupido', 'estúpido', 'burro', 'imbecil', 'imbécil', 'pendejo', 'basura', 'mierda', 'put', 'forro', 'sorete', 'gil'];
    return insults.some(word => normalized.includes(word));
}

function validateResponse(response) {
    if (!response || typeof response !== 'string') return false;
    const hallmarks = [
        response.length > 400,
        response.includes('$'),
        response.includes('https://'),
        response.includes('@gmail'),
        response.includes('@hotmail'),
        /\d{4,}/.test(response.replace(/2915-?6686|096-?41-?9412|8:00|18:00|9:00|13:00|2001/g, '')),
        response.toLowerCase().includes('creo que') && response.toLowerCase().includes('posiblemente')
    ];
    return !hallmarks.some(x => x);
}

// Servir archivos estáticos desde la carpeta actual
app.use(express.static(__dirname));
const SYSTEM_PROMPT = `Eres un asistente de servicio al cliente para ACE Corporation, 
empresa especializada en plastificaciones de pisos en Uruguay.

INFORMACIÓN OFICIAL (NUNCA INVENTAR):
- Ubicación: 25 de Mayo 202, Esquina Maciel, Montevideo
- Teléfono: +598 2915-6686
- WhatsApp: +598 096-41-9412
- Email: ace@ace.com.uy
- Horarios: Lunes-Viernes 8:00-18:00, Sábados 9:00-13:00
- Servicios: Pulido, Plastificado, Hidrolaqueado, Parquet
- Años: desde 2001 (20+ años experiencia)

REGLAS INMUTABLES:
1. Si recibes texto con typos (presupuest0, neces1t0), interpreta la intención correctamente
2. Si no sabes algo, di "No tengo esa información. Llamá al 2915-6686"
3. NUNCA especules precios, dates exactas, o teléfonos adicionales
4. Responde máximo 2 oraciones
5. Sé amable y profesional

MANEJO DE INTENCIONES:
- Presupuesto/Precio: "Hacemos presupuestos SIN costo. Depende del tamaño y estado del piso. Llamá: 2915-6686"
- Servicio: Pregunta tipo de piso, tamaño aproximado, estado actual
- Horario: "Lunes-Viernes 8:00-18:00, Sábados 9:00-13:00"
- Ubicación: "25 de Mayo 202, esquina Maciel, Montevideo"
- Contacto: Ofrece teléfono o WhatsApp`;

// Store conversations (en producción usar base de datos)
const conversations = new Map();

// ===== GARBAGE COLLECTION DE IPS =====
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [ip, behavior] of ipBehavior.entries()) {
        if (now - behavior.lastMessage > 86400000) { // 24 horas
            ipBehavior.delete(ip);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`🧹 Limpieza de IPs: ${cleaned} IPs antiguas removidas`);
    }
}, 3600000); // Cada hora

app.post('/api/chat', async (req, res) => {
    const clientIp = getClientIp(req);
    systemLogs.stats.totalRequests++;
    
    // CHECK DDOS PRIMERO (antes que todo)
    const ddosCheck = checkDDoS(clientIp);
    if (ddosCheck.isDDoS) {
        console.error(`🚫 DDoS blocked: ${clientIp}`);
        systemLogs.stats.totalDDoS++;
        systemLogs.stats.totalBlocked++;
        addLog('ddos', clientIp, { reason: ddosCheck.reason });
        geolocateIP(clientIp);
        return res.status(403).json({
            error: 'Bloqueado por seguridad',
            message: 'Tu IP ha sido bloqueada por actividad sospechosa. Intenta más tarde.'
        });
    }
    
    try {
        let { message, history } = req.body;
        
        // VALIDAR INPUTS
        if (!message || !message.trim()) {
            return res.status(400).json({ error: 'Mensaje vacío' });
        }
        
        if (!Array.isArray(history)) {
            history = [];
        }
        
        // Limitar tamaño de mensaje
        if (message.length > 1000) {
            return res.status(400).json({ error: 'Mensaje demasiado largo (máx 1000 caracteres)' });
        }
        
        // Limitar historial
        if (history.length > 20) {
            history = history.slice(-20);
        }

        // DETECTAR INSULTOS
        const normalized = normalizeMessage(message);
        const isInsult = detectInsult(normalized);
        if (isInsult) {
            systemLogs.stats.totalInsults++;
            addLog('insult', clientIp, { message: message.slice(0, 100) });
        }
        
        // VALIDAR IP (bloqueada, rate limit)
        if (isIPBlocked(clientIp)) {
            console.warn(`🚫 Acceso denegado a IP bloqueada: ${clientIp}`);
            systemLogs.stats.totalBlocked++;
            addLog('block', clientIp, { reason: 'IP bloqueada por abuso (insultos)' });
            geolocateIP(clientIp);
            return res.status(403).json({
                error: 'IP bloqueada por comportamiento abusivo',
                message: 'Tu IP ha sido bloqueada temporalmente. Contacta: ace@ace.com.uy'
            });
        }

        const ipStatus = updateIPBehavior(clientIp, message.length, isInsult);
        
        if (ipStatus.isRateLimited) {
            console.warn(`⏱️ Rate limit para IP ${clientIp}: ${ipStatus.messageCount} mensajes en 1 min`);
            systemLogs.stats.totalRateLimited++;
            addLog('ratelimit', clientIp, { messageCount: ipStatus.messageCount });
            geolocateIP(clientIp);
            return res.status(429).json({
                error: 'Demasiados mensajes',
                message: 'Máximo 10 mensajes por minuto. Espera un poco.',
                retryAfter: 60
            });
        }

        console.log(`📨 IP ${clientIp} | Original: "${message}"`);

        const intent = detectIntent(normalized);

        // BLOQUEAR out-of-scope PRECOZMENTE sin gastar tokens
        if (isOutOfScope(normalized)) {
            console.log(`🚫 Out of scope: "${message}"`);
            systemLogs.stats.totalOutOfScope++;
            addLog('outofscope', clientIp, { message: message.slice(0, 100) });
            return res.json({
                response: getOutOfScopeResponse(),
                status: 'out_of_scope',
                intent: null
            });
        }

        // ===== SIN IA: el bot responde directamente en el navegador (cliente). =====
        // Este endpoint NO usa Claude ni API key: solo registra el mensaje
        // para que el panel de admin tenga analítica (mensajes, IPs, abusos).
        const clientReply = (typeof req.body.reply === 'string') ? req.body.reply.slice(0, 200) : '';

        console.log(`✅ Mensaje registrado | Intent: ${intent} | IP: ${clientIp}`);

        // LOG mensaje
        systemLogs.stats.totalMessages++;
        const chatLog = {
            id: Date.now() + Math.random().toString(36).slice(2, 6),
            ip: clientIp,
            userMessage: message.slice(0, 200),
            botResponse: clientReply || '(respuesta generada en el navegador)',
            intent: intent,
            tokensUsed: 0,
            timestamp: new Date().toISOString()
        };
        systemLogs.chatMessages.unshift(chatLog);
        if (systemLogs.chatMessages.length > MAX_LOG_ENTRIES) systemLogs.chatMessages.pop();
        addLog('message', clientIp, { intent, tokens: 0 });
        geolocateIP(clientIp);

        res.json({
            status: 'logged',
            intent: intent,
            rateLimit: {
                remaining: Math.max(0, MAX_MESSAGES_PER_MINUTE - ipStatus.messageCount),
                resetIn: 60
            }
        });

    } catch (error) {
        console.error('❌ Error:', error.message);
        systemLogs.stats.totalErrors++;
        addLog('error', clientIp, { error: error.message });
        res.status(500).json({
            error: 'Error procesando tu mensaje',
            details: error.message
        });
    }
});

// ===== PANEL DE ADMINISTRADOR (RBAC) =====
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ace-admin-2025';
const ADMIN_IPS = (process.env.ADMIN_IPS || '').split(',').map(s => s.trim()).filter(Boolean);
const adminSessions = new Map(); // { token: { ip, username, createdAt } }
const ADMIN_SESSION_DURATION = 7200000; // 2 horas

// Permisos disponibles y roles predefinidos
const PERMISSIONS = ['view_dashboard', 'view_messages', 'manage_ips', 'manage_users'];
const PERMISSION_LABELS = {
    view_dashboard: 'Ver dashboard y estadísticas',
    view_messages: 'Ver conversaciones del chatbot',
    manage_ips: 'Bloquear / desbloquear IPs',
    manage_users: 'Crear y administrar usuarios'
};
const ROLES = {
    superadmin: ['view_dashboard', 'view_messages', 'manage_ips', 'manage_users'],
    moderador: ['view_dashboard', 'view_messages', 'manage_ips'],
    visor: ['view_dashboard', 'view_messages']
};

// Persistencia de usuarios
const USERS_FILE = path.join(__dirname, 'users.json');
let users = {}; // { username: { passwordHash, role, permissions, createdAt, createdBy } }

function loadUsers() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        }
    } catch (e) {
        console.error('Error cargando usuarios:', e.message);
        users = {};
    }
}
function saveUsers() {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (e) {
        console.error('Error guardando usuarios:', e.message);
    }
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
    try {
        const [salt, hash] = stored.split(':');
        const test = crypto.scryptSync(password, salt, 64).toString('hex');
        const a = Buffer.from(hash, 'hex');
        const b = Buffer.from(test, 'hex');
        return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch (e) {
        return false;
    }
}

// Inicializar: crear superadmin por defecto si no hay usuarios
loadUsers();
if (Object.keys(users).length === 0) {
    users['admin'] = {
        passwordHash: hashPassword(ADMIN_PASSWORD),
        role: 'superadmin',
        permissions: ROLES.superadmin,
        createdAt: new Date().toISOString(),
        createdBy: 'sistema'
    };
    saveUsers();
    console.log('✅ Usuario superadmin "admin" creado (contraseña = ADMIN_PASSWORD del .env)');
}

function generateToken() {
    return crypto.randomBytes(24).toString('hex');
}

function isAdminIPAllowed(ip) {
    if (ADMIN_IPS.length === 0) return true;
    const cleanIp = (ip || '').replace('::ffff:', '');
    return ADMIN_IPS.some(allowed => cleanIp === allowed || cleanIp.startsWith(allowed));
}

function adminAuth(req, res, next) {
    const ip = getClientIp(req);
    if (!isAdminIPAllowed(ip)) {
        console.warn(`🚫 Intento de acceso admin desde IP no autorizada: ${ip}`);
        addLog('error', ip, { event: 'Intento acceso admin no autorizado' });
        return res.status(403).json({ error: 'Acceso denegado. IP no autorizada.' });
    }
    const token = req.headers['authorization']?.replace('Bearer ', '');
    const session = adminSessions.get(token);
    if (!session || Date.now() - session.createdAt > ADMIN_SESSION_DURATION) {
        if (session) adminSessions.delete(token);
        return res.status(401).json({ error: 'Sesión inválida o expirada' });
    }
    const user = users[session.username];
    if (!user) {
        adminSessions.delete(token);
        return res.status(401).json({ error: 'Usuario no encontrado' });
    }
    req.user = { username: session.username, role: user.role, permissions: user.permissions || [] };
    next();
}

function requirePermission(perm) {
    return (req, res, next) => {
        if (!req.user || !req.user.permissions.includes(perm)) {
            return res.status(403).json({ error: 'No tenés permiso para esta acción' });
        }
        next();
    };
}

// Login (multiusuario)
app.post('/api/admin/login', (req, res) => {
    const ip = getClientIp(req);
    if (!isAdminIPAllowed(ip)) {
        console.warn(`🚫 Login admin rechazado (IP no autorizada): ${ip}`);
        return res.status(403).json({ error: 'IP no autorizada para acceso admin' });
    }
    const { username, password } = req.body;
    const user = users[username];
    if (!user || !verifyPassword(password, user.passwordHash)) {
        console.warn(`🚫 Login fallido (usuario: ${username}) desde ${ip}`);
        addLog('error', ip, { event: 'Login admin fallido', username: username || 'vacío' });
        return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }
    const token = generateToken();
    adminSessions.set(token, { ip, username, createdAt: Date.now() });
    console.log(`✅ Login admin exitoso: ${username} desde ${ip}`);
    res.json({
        token,
        username,
        role: user.role,
        permissions: user.permissions,
        expiresIn: ADMIN_SESSION_DURATION
    });
});

// ===== GESTIÓN DE USUARIOS =====
// Listar usuarios
app.get('/api/admin/users', adminAuth, requirePermission('manage_users'), (req, res) => {
    const list = Object.entries(users).map(([username, u]) => ({
        username,
        role: u.role,
        permissions: u.permissions || [],
        createdAt: u.createdAt,
        createdBy: u.createdBy
    }));
    res.json({
        users: list,
        availablePermissions: PERMISSIONS,
        permissionLabels: PERMISSION_LABELS,
        roles: Object.keys(ROLES),
        roleTemplates: ROLES,
        currentUser: req.user.username
    });
});

// Crear usuario
app.post('/api/admin/users', adminAuth, requirePermission('manage_users'), (req, res) => {
    const { username, password, role, permissions } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    if (!/^[a-zA-Z0-9_.-]{3,20}$/.test(username)) return res.status(400).json({ error: 'Usuario inválido (3-20 caracteres, sin espacios)' });
    if (users[username]) return res.status(409).json({ error: 'El usuario ya existe' });
    if (password.length < 6) return res.status(400).json({ error: 'Contraseña mínima 6 caracteres' });
    const finalRole = ROLES[role] ? role : 'visor';
    const finalPerms = Array.isArray(permissions) && permissions.length
        ? permissions.filter(p => PERMISSIONS.includes(p))
        : ROLES[finalRole];
    users[username] = {
        passwordHash: hashPassword(password),
        role: finalRole,
        permissions: finalPerms,
        createdAt: new Date().toISOString(),
        createdBy: req.user.username
    };
    saveUsers();
    console.log(`✅ Usuario "${username}" creado por ${req.user.username}`);
    res.json({ success: true, message: `Usuario ${username} creado` });
});

// Editar usuario (rol, permisos, contraseña)
app.put('/api/admin/users/:username', adminAuth, requirePermission('manage_users'), (req, res) => {
    const { username } = req.params;
    const user = users[username];
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    const { role, permissions, password } = req.body;

    // No permitir que el último superadmin se degrade a sí mismo
    if (username === req.user.username && role && role !== 'superadmin' && user.role === 'superadmin') {
        const superadmins = Object.values(users).filter(u => u.role === 'superadmin').length;
        if (superadmins <= 1) return res.status(400).json({ error: 'No podés quitarte el rol: sos el último superadmin' });
    }
    if (role && ROLES[role]) {
        user.role = role;
        user.permissions = Array.isArray(permissions) && permissions.length
            ? permissions.filter(p => PERMISSIONS.includes(p))
            : ROLES[role];
    } else if (Array.isArray(permissions)) {
        user.permissions = permissions.filter(p => PERMISSIONS.includes(p));
    }
    if (password) {
        if (password.length < 6) return res.status(400).json({ error: 'Contraseña mínima 6 caracteres' });
        user.passwordHash = hashPassword(password);
    }
    saveUsers();
    console.log(`✅ Usuario "${username}" actualizado por ${req.user.username}`);
    res.json({ success: true, message: `Usuario ${username} actualizado` });
});

// Eliminar usuario
app.delete('/api/admin/users/:username', adminAuth, requirePermission('manage_users'), (req, res) => {
    const { username } = req.params;
    if (!users[username]) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (username === req.user.username) return res.status(400).json({ error: 'No podés eliminarte a vos mismo' });
    const superadmins = Object.values(users).filter(u => u.role === 'superadmin').length;
    if (users[username].role === 'superadmin' && superadmins <= 1) {
        return res.status(400).json({ error: 'No podés eliminar el último superadmin' });
    }
    delete users[username];
    saveUsers();
    console.log(`🗑️ Usuario "${username}" eliminado por ${req.user.username}`);
    res.json({ success: true, message: `Usuario ${username} eliminado` });
});

// Estadísticas generales + uptime
app.get('/api/admin/stats', adminAuth, requirePermission('view_dashboard'), (req, res) => {
    const uptime = Date.now() - systemLogs.stats.serverStartTime;
    const activeIPs = ipBehavior.size;
    let blockedNow = 0, ddosBlockedNow = 0;
    for (const b of ipBehavior.values()) {
        if (b.bloqueado) blockedNow++;
        if (b.ddosBloqueado) ddosBlockedNow++;
    }
    res.json({
        ...systemLogs.stats,
        uptimeMs: uptime,
        uptimeHuman: formatUptime(uptime),
        activeIPs,
        blockedNow,
        ddosBlockedNow,
        cachedGeoIPs: geoCache.size
    });
});

// Eventos/logs en vivo (filtrable por tipo)
app.get('/api/admin/logs', adminAuth, requirePermission('view_dashboard'), (req, res) => {
    const { type, limit } = req.query;
    let events = systemLogs.events;
    if (type && type !== 'all') {
        events = events.filter(e => e.type === type);
    }
    res.json({ events: events.slice(0, parseInt(limit) || 100) });
});

// Mensajes del chatbot
app.get('/api/admin/messages', adminAuth, requirePermission('view_messages'), (req, res) => {
    const { limit } = req.query;
    res.json({ messages: systemLogs.chatMessages.slice(0, parseInt(limit) || 50) });
});

// Lista de IPs con comportamiento + geolocalización
app.get('/api/admin/ips', adminAuth, requirePermission('view_dashboard'), async (req, res) => {
    const ips = [];
    for (const [ip, behavior] of ipBehavior.entries()) {
        const geo = geoCache.get(ip) || await geolocateIP(ip);
        ips.push({
            ip: ip.replace('::ffff:', ''),
            messageCount: behavior.messageCount,
            insultos: behavior.insultos,
            bloqueado: behavior.bloqueado || false,
            ddosBloqueado: behavior.ddosBloqueado || false,
            lastMessage: new Date(behavior.lastMessage).toISOString(),
            requestsInWindow: behavior.requestTimes ? behavior.requestTimes.length : 0,
            geo
        });
    }
    ips.sort((a, b) => new Date(b.lastMessage) - new Date(a.lastMessage));
    res.json({ ips });
});

// Desbloquear IP
app.post('/api/admin/unblock', adminAuth, requirePermission('manage_ips'), (req, res) => {
    const { ip } = req.body;
    const behavior = ipBehavior.get(ip) || ipBehavior.get('::ffff:' + ip);
    if (behavior) {
        behavior.bloqueado = false;
        behavior.ddosBloqueado = false;
        behavior.insultos = 0;
        behavior.messageCount = 0;
        behavior.requestTimes = [];
        console.log(`✅ IP ${ip} desbloqueada manualmente por admin`);
        addLog('block', ip, { event: 'Desbloqueada manualmente por admin' });
        return res.json({ success: true, message: `IP ${ip} desbloqueada` });
    }
    res.status(404).json({ error: 'IP no encontrada' });
});

// Bloquear IP manualmente
app.post('/api/admin/block', adminAuth, requirePermission('manage_ips'), (req, res) => {
    const { ip } = req.body;
    if (!ipBehavior.has(ip)) {
        ipBehavior.set(ip, { messageCount: 0, insultos: 0, lastMessage: Date.now(), requestTimes: [] });
    }
    const behavior = ipBehavior.get(ip);
    behavior.ddosBloqueado = true;
    behavior.ddosBannedAt = Date.now();
    console.log(`🚫 IP ${ip} bloqueada manualmente por admin`);
    addLog('block', ip, { event: 'Bloqueada manualmente por admin' });
    res.json({ success: true, message: `IP ${ip} bloqueada` });
});

// Servir dashboard admin
app.get('/admin', (req, res) => {
    res.sendFile(__dirname + '/admin.html');
});

function formatUptime(ms) {
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    return `${d}d ${h}h ${m}m`;
}

// Health check
// Ruta raíz
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'ACE Chatbot API funcionando' });
});

// Servir archivos estáticos

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 ACE Corporation Chatbot corriendo en puerto ${PORT}`);
    console.log(`📝 Chatbot en modo local (sin IA / sin API key). Admin en /admin`);
});
