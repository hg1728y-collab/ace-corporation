# 🤖 ACE Corporation - Chatbot IA con Claude
## Guía Completa de Instalación y Configuración

---

## 📋 Lo que tienes:

✅ **ace-corporation-con-chatbot.html** - Página web con chatbot flotante
✅ **server.js** - Backend Node.js con Claude IA
✅ **Esta guía** - Instrucciones paso a paso

---

## ⚡ INSTALACIÓN RÁPIDA (5 minutos)

### PASO 1: Obtener API Key de Anthropic
1. Ve a https://console.anthropic.com/
2. Crea una cuenta (gratis)
3. Ve a **API Keys** → **Create Key**
4. **Copia la clave ENTERA** (será algo como `sk-ant-api03-KJ5Yf92pXkL8nM3qR7vWxZ...` — muy larga, ~110 caracteres)
5. Guardala en un lugar seguro

⚠️ **Formato correcto:** `sk-ant-api03-...` (larguísima)  
❌ **NO es válido:** `sk-ant-v6-...` (ese formato no existe — es un error de guías viejas)

### PASO 2: Instalar Node.js
- Descarga de https://nodejs.org/ (versión LTS)
- Instala normalmente
- Verifica: `node -v` en terminal

### PASO 3: Configurar Proyecto

```bash
# Crear carpeta del proyecto
mkdir ace-corporation
cd ace-corporation

# Crear archivo package.json
npm init -y

# Instalar dependencias
npm install express anthropic dotenv cors
```

### PASO 4: Crear archivo .env
Crea un archivo llamado `.env` en tu carpeta con:

```
ANTHROPIC_API_KEY=sk-ant-v6-TU-CLAVE-AQUI
PORT=3000
```

⚠️ **IMPORTANTE**: Reemplaza `TU-CLAVE-AQUI` con tu clave real

### PASO 5: Archivos en tu carpeta

Tu carpeta debe tener:
```
ace-corporation/
├── server.js
├── .env
├── package.json
└── public/
    └── index.html (renombra ace-corporation-con-chatbot.html aquí)
```

### PASO 6: Ejecutar

```bash
# En terminal, desde tu carpeta:
node server.js

# Deberías ver:
# 🚀 ACE Corporation Chatbot corriendo en puerto 3000
```

### PASO 7: Acceder
Abre en el navegador:
```
http://localhost:3000
```

---

## 🚀 DESPLEGAR EN DigitalOcean App Platform (RECOMENDADO)

**Esto es lo que estás usando. Seguí esto paso a paso.**

### Requisitos previos:
- Repositorio en GitHub con tu proyecto
- Cuenta en DigitalOcean
- Clave API de Anthropic (real, no la vieja falsa)

### Pasos:

1. **En DigitalOcean App Platform:**
   - Ve a "Apps" → "Create App"
   - Conecta tu repositorio de GitHub
   - Selecciona la rama (main)

2. **Configuración del app:**
   - Selecciona "Node.js" como tipo
   - HTTP Port: `3000` (o deja automático)

3. **Environment Variables (AQUÍ VA LA CLAVE):**
   - Click en tu componente → "Settings" → "Environment Variables"
   - **Agrega estas variables:**
     ```
     ANTHROPIC_API_KEY = (pega tu clave real aquí, ej: sk-ant-api03-...)
     ```
     Marcala como **Encrypted** 🔒
   - (Opcional) Si quieres cambiar contraseña admin:
     ```
     ADMIN_PASSWORD = tu-super-contraseña-fuerte
     ```
   - Guardá

4. **Deploy:**
   - DigitalOcean detecta el package.json y corre `npm start` automáticamente
   - Esperá a que termine (verde = listo)
   - Tu sitio está en línea en: `https://tuapp-xxxx.ondigitalocean.app`

**❌ NO hagas esto:**
- No subas el archivo `.env` a GitHub (ya está en .gitignore, bien)
- No uses la clave vieja falsa (`sk-ant-v6-...`)

---
1. Crea cuenta en https://heroku.com
2. Descarga Heroku CLI
3. Desde tu carpeta:
   ```bash
   heroku login
   heroku create nombre-app
   git push heroku main
   heroku config:set ANTHROPIC_API_KEY=sk-ant-...
   ```

### OPCIÓN B: Railway (RECOMENDADO - MÁS FÁCIL)
1. Ve a https://railway.app
2. Conecta tu GitHub
3. Importa tu repositorio
4. Agrega variable ANTHROPIC_API_KEY en settings
5. Listo ✅

### OPCIÓN C: Replit
1. Importa tu proyecto a https://replit.com
2. Crea archivo `.env` con tu API Key
3. Click "Run"
4. Listo

---

## 💬 Cómo funciona el Chatbot

### Flujo de Conversación:
```
Cliente entra en web
    ↓
Ve botón 💬 en esquina
    ↓
Hace pregunta: "¿Qué es plastificado?"
    ↓
Claude IA responde profesionalmente
    ↓
Chatbot pregunta: "¿Qué tipo de piso tienes?"
    ↓
Cliente responde
    ↓
Chatbot sugiere servicio
    ↓
Invita a llenar formulario
```

### Ejemplos de Preguntas:
- ✅ "¿Qué es el plastificado?"
- ✅ "¿Cuál es su ubicación?"
- ✅ "Tengo un piso de madera rayado"
- ✅ "¿Cuánto cuesta?"
- ✅ "¿Atienden los sábados?"

---

## 📧 Formulario + Email

El formulario usa **FormSubmit.co** (gratis):
- Los datos se envían a: `ace@ace.com.uy`
- No necesita backend adicional
- Los correos llegan al instante

Para cambiar el email, edita en `ace-corporation-con-chatbot.html`:
```html
<form action="https://formsubmit.co/TU-EMAIL@aqui.com" method="POST">
```

---

## 🔧 Personalizar el Chatbot

### Cambiar nombre/idioma:
En `server.js`, modifica `SYSTEM_PROMPT`:

```javascript
const SYSTEM_PROMPT = `Eres un asistente...
[Personaliza aquí la personalidad del bot]
`;
```

### Agregar más información:
Añade en INFORMACIÓN SOBRE ACE:

```javascript
- Promoción: "Descuento 20% en plastificado este mes"
- WhatsApp: Enlace directo
```

### Cambiar tono:
- Profesional: "Le recomiendo el servicio X"
- Casual: "Te recomiendo que uses X"

---

## 📊 Monitoreo

### Ver conversaciones en tiempo real:
Los logs se ven en terminal:

```
📨 Mensaje del usuario: Hola, ¿qué ofertas tienen?
📋 Historial: 3 mensajes
✅ Respuesta del bot: Tenemos descuentos especiales...
```

En producción, guarda en base de datos (PostgreSQL, MongoDB, Firebase).

---

## 🐛 El chatbot se queda en "Escribiendo..."

### Causas y soluciones:

**1. La API key es inválida o falsa** ← Esta es la más común
   - ✅ Verificá que empiece con `sk-ant-api03-` y sea **muy larga** (~110 caracteres)
   - ❌ Si dice `sk-ant-v6-...` o es corta, NO es válida
   - **Solución:** Obtené una nueva en https://console.anthropic.com/

**2. La variable ANTHROPIC_API_KEY no está configurada en DigitalOcean**
   - ✅ En tu app → Settings → Environment Variables, verificá que esté:
   ```
   ANTHROPIC_API_KEY = sk-ant-api03-TU-CLAVE-REAL
   ```
   - Marcala como Encrypted 🔒
   - Guardá y redespliega

**3. El servidor no está corriendo (si lo corrés localmente)**
   - Abrí terminal en tu carpeta y corre:
   ```bash
   node server.js
   ```
   - Deberías ver: `🚀 ACE Corporation Chatbot corriendo en puerto 3000`

**4. Revisá los logs del servidor:**
   - Si estás en DigitalOcean, ve a tu app → "Logs"
   - Si corrés localmente, mirá la terminal donde corriste `node server.js`
   - Buscá líneas que digan `❌ Error` o `Invalid API Key`

---
- ✅ Crea archivo `.env`
- ✅ Agrega tu clave real
- ✅ Reinicia el servidor

### Error: "Cannot find module 'express'"
- ✅ Ejecuta: `npm install`

### El chatbot no responde
- ✅ Verifica conexión a internet
- ✅ Comprueba que tu API Key es válida
- ✅ Abre consola del navegador (F12) para ver errores

### "Connection refused" al abrir localhost:3000
- ✅ Verifica que el servidor está corriendo (`node server.js`)
- ✅ Intenta puerto diferente: `PORT=3001 node server.js`

---

## 💰 Costos

| Servicio | Costo | Incluye |
|----------|-------|---------|
| **Anthropic API** | $0.80-$8 por 1M tokens | Respuestas del chatbot |
| **Hosting (Railway)** | GRATIS | Servidor siempre activo |
| **FormSubmit** | GRATIS | Formularios → Email |
| **Total mensual** | ~$5-20 | Todo funcionando |

Con 1000 usuarios al mes, gastas ~$10-20.

---

## 📈 Próximos Pasos

1. ✅ Instala todo (hoy)
2. ✅ Prueba localmente
3. ✅ Deploya en internet
4. ✅ Monitorea conversaciones
5. ✅ Ajusta respuestas del bot según feedback

---

## 🎯 Niveles de IA

Tu chatbot está configurado con:
- **Nivel Medio** ✅ (recomendado)
  - Entiende contexto
  - Responde preguntas complejas
  - Personalizadas para ACE
  - Sugiere servicios inteligentemente

Puedes cambiar a:
- **Nivel Básico**: Solo respuestas predefinidas
- **Nivel Avanzado**: Integraciones complejas, análisis

---

## ❓ ¿Preguntas?

Si algo no funciona:
1. Verifica .env tiene tu API Key
2. Asegúrate Node.js está instalado
3. Revisa logs en terminal
4. Contacta a Anthropic support

---

## 📝 Checklist de Configuración

- [ ] API Key de Anthropic obtenida
- [ ] Node.js instalado
- [ ] Dependencias instaladas (`npm install`)
- [ ] Archivo .env creado con clave
- [ ] server.js en carpeta
- [ ] HTML en carpeta `public/`
- [ ] Ejecutado `node server.js`
- [ ] Abierto http://localhost:3000
- [ ] Chatbot responde
- [ ] Formulario envía email
- [ ] Desplegado en internet (opcional)

---

**¡Tu sitio profesional con IA está listo! 🎉**
