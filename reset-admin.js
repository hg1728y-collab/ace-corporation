const fs = require('fs');
const crypto = require('crypto');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ace-admin-2025';

// MISMO formato que server.js: salt:hash con salt aleatorio
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

const users = {
    admin: {
        passwordHash: hashPassword(ADMIN_PASSWORD),
        role: 'superadmin',
        permissions: ['view_dashboard', 'view_messages', 'manage_ips', 'manage_users'],
        createdAt: new Date().toISOString(),
        createdBy: 'system'
    }
};

fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
console.log('✅ Admin reseteado correctamente');
console.log('   Usuario: admin');
console.log('   Contraseña:', ADMIN_PASSWORD);
