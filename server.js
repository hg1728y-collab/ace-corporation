// server.js - Backend para ACE Corporation con Chatbot IA
// npm install express anthropic dotenv cors

const express = require('express');
const { Anthropic } = require('@anthropic-ai/sdk');
const cors = require('cors');
const dotenv = require('dotenv');

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

// ===== NORMALIZACIÓN Y DETECCIÓN DE INTENT =====
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
    
    // CHECK DDOS PRIMERO (antes que todo)
    const ddosCheck = checkDDoS(clientIp);
    if (ddosCheck.isDDoS) {
        console.error(`🚫 DDoS blocked: ${clientIp}`);
        return res.status(403).json({
            error: 'Bloqueado por seguridad',
            message: 'Tu IP ha sido bloqueada por actividad sospechosa. Intenta más tarde.'
        });
    }
    
    try {
        
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
        
        // VALIDAR IP (bloqueada, rate limit)
        if (isIPBlocked(clientIp)) {
            console.warn(`🚫 Acceso denegado a IP bloqueada: ${clientIp}`);
            return res.status(403).json({
                error: 'IP bloqueada por comportamiento abusivo',
                message: 'Tu IP ha sido bloqueada temporalmente. Contacta: ace@ace.com.uy'
            });
        }

        const ipStatus = updateIPBehavior(clientIp, message.length, isInsult);
        
        if (ipStatus.isRateLimited) {
            console.warn(`⏱️ Rate limit para IP ${clientIp}: ${ipStatus.messageCount} mensajes en 1 min`);
            return res.status(429).json({
                error: 'Demasiados mensajes',
                message: 'Máximo 10 mensajes por minuto. Espera un poco.',
                retryAfter: 60
            });
        }

        console.log(`📨 IP ${clientIp} | Original: "${message}"`);
        console.log(`📝 Normalizado: "${normalized}" | Insulto: ${isInsult}`);

        const intent = detectIntent(normalized);

        // BLOQUEAR out-of-scope PRECOZMENTE sin gastar tokens
        if (isOutOfScope(normalized)) {
            console.log(`🚫 Out of scope: "${message}"`);
            return res.json({
                response: getOutOfScopeResponse(),
                status: 'out_of_scope',
                intent: null
            });
        }

        // Crear conversación con historial (validado)
        const messages = history
            .filter(msg => msg && msg.role && msg.content && typeof msg.content === 'string')
            .map(msg => ({
                role: msg.role === 'user' || msg.role === 'assistant' ? msg.role : 'user',
                content: msg.content.trim().slice(0, 500) // Max 500 chars por msg
            }));

        let userMessage = message;
        if (intent) {
            userMessage = `[INTENT: ${intent}] ${message}`;
        }
        messages.push({ role: 'user', content: userMessage });

        // Llamar a Claude con timeout (30s)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);
        
        let botResponse;
        try {
            const response = await client.messages.create({
                model: 'claude-3-5-sonnet-20241022',
                max_tokens: 150,
                system: SYSTEM_PROMPT,
                messages: messages
            });
            botResponse = response.content[0].text;
        } finally {
            clearTimeout(timeoutId);
        }
        
        // VALIDAR salida (rechazar alucinaciones)
        if (!validateResponse(botResponse)) {
            console.warn('⚠️ Alucinación detectada, usando fallback');
            botResponse = "No tengo esa información. Llamá al 2915-6686 para consultas personalizadas.";
        }
        
        console.log(`✅ Respuesta: "${botResponse}"`);
        console.log(`📊 Tokens: ${response.usage.output_tokens} | IP: ${clientIp}`);

        res.json({
            response: botResponse,
            status: 'success',
            intent: intent,
            rateLimit: {
                remaining: Math.max(0, MAX_MESSAGES_PER_MINUTE - ipStatus.messageCount),
                resetIn: 60
            }
        });

    } catch (error) {
        console.error('❌ Error:', error.message);
        res.status(500).json({
            error: 'Error procesando tu mensaje',
            details: error.message
        });
    }
});

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
    console.log(`📝 Asegúrate de tener ANTHROPIC_API_KEY en .env`);
});
