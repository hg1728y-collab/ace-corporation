// server.js - Backend para ACE Corporation con Chatbot IA
// VERSIÓN CORREGIDA PARA DIGITALOCEAN

const express = require('express');
const { Anthropic } = require('@anthropic-ai/sdk');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const client = new Anthropic();

// Servir archivos estáticos desde la carpeta actual
app.use(express.static(path.join(__dirname)));

// Sistema de contexto para el chatbot
const SYSTEM_PROMPT = `Eres un asistente de servicio al cliente profesional para ACE Corporation, 
la empresa #1 en plastificaciones de pisos en Uruguay. 

INFORMACIÓN SOBRE ACE:
- Fundada: 2001
- Servicios: Pulido, Plastificado, Hidrolaqueado, Instalación de Parquet, Reparación
- Ubicación: 25 de Mayo 202, Esquina Maciel, Montevideo
- Teléfono: +598 2915-6686
- Celular/WhatsApp: +598 096-41-9412
- Email: ace@ace.com.uy
- Horarios: Lunes-Viernes 8:00-18:00, Sábados 9:00-13:00
- Proyectos completados: 5000+
- Años de experiencia: 20+
- Satisfacción: 98%

INSTRUCCIONES:
1. Sé amable, profesional y conciso
2. Responde preguntas sobre servicios, ubicación, horarios, precios
3. Haz preguntas para entender el problema del cliente:
   - ¿Qué tipo de piso tiene? (madera, parquet, etc)
   - ¿Cuál es el tamaño aproximado del área?
   - ¿Cuál es el estado actual? (nuevo, dañado, rayado, etc)
   - ¿Qué servicio le interesa? (pulido, plastificado, etc)
   - ¿Cuándo lo necesita?
4. Basado en sus respuestas, sugiere el servicio más apropiado
5. Invita al cliente a llenar el formulario o contactar directamente
6. Si el cliente tiene preguntas complejas, sugiere un contacto directo

RESPUESTAS A PREGUNTAS COMUNES:
- Presupuesto: "Hacemos presupuestos sin compromiso. Depende del tamaño y estado del piso."
- Tiempo: "Pulido: 1-2 días. Plastificado: 1-3 días. Consulta según tu urgencia."
- Garantía: "Garantizamos satisfacción en todos nuestros trabajos."
- Precio: "Presupuesto sin costo. Contacta para detalles específicos."

Mantén respuestas entre 1-3 oraciones. Si es necesario más información, pregunta.`;

// API del Chatbot
app.post('/api/chat', async (req, res) => {
    try {
        const { message, history } = req.body;
        
        if (!message || !message.trim()) {
            return res.status(400).json({ error: 'Mensaje vacío' });
        }

        // Crear conversación con historial
        const messages = history.map(msg => ({
            role: msg.role,
            content: msg.content
        }));

        console.log('📨 Mensaje del usuario:', message);
        console.log('📋 Historial:', messages.length, 'mensajes');

        // Llamar a Claude
        const response = await client.messages.create({
            model: 'claude-3-5-sonnet-20241022',
            max_tokens: 300,
            system: SYSTEM_PROMPT,
            messages: messages
        });

        const botResponse = response.content[0].text;
        
        console.log('✅ Respuesta del bot:', botResponse);

        res.json({
            response: botResponse,
            status: 'success'
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
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'ACE Chatbot API funcionando' });
});

// Ruta raíz para index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 ACE Corporation Chatbot corriendo en puerto ${PORT}`);
    console.log(`📝 Asegúrate de tener ANTHROPIC_API_KEY en .env`);
});
