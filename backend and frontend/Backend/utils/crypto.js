const crypto = require('crypto');

const ALGORITHM = 'aes-256-cbc';

// 32-byte key from env or a default (set ENCRYPTION_KEY in .env for production)
const KEY = Buffer.from(
  (process.env.ENCRYPTION_KEY || 'wazuhbot-default-encrypt-key-32b').slice(0, 32).padEnd(32, '0')
);

function encrypt(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(stored) {
  if (!stored) return '';
  try {
    const [ivHex, encHex] = stored.split(':');
    const iv        = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encHex, 'hex');
    const decipher  = crypto.createDecipheriv(ALGORITHM, KEY, iv);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  } catch {
    return '';
  }
}

module.exports = { encrypt, decrypt };
