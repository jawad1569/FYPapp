const bcrypt = require('bcryptjs');

/* ── Get the pool attached by server.js ── */
function getDb(req) {
  // When called from routes, req is the Express request object.
  // We also expose a setter so server.js can push the pool in.
  return getDb._pool;
}
getDb.setPool = (pool) => { getDb._pool = pool; };

/* ── Row mapper: MySQL snake_case → camelCase ── */
function mapRow(row, includePassword = false) {
  const user = {
    _id:              row.id,
    fullName:         row.full_name,
    email:            row.email,
    organization:     row.organization       || '',
    wazuhIp:          row.wazuh_ip           || '',       // Manager API IP (port 55000)
    wazuhIndexerIp:   row.wazuh_indexer_ip   || '',       // Indexer IP (port 9200); falls back to wazuhIp
    wazuhUser:        row.wazuh_user         || '',
    wazuhPassword:    row.wazuh_password     || '',
    wazuhApiUser:     row.wazuh_api_user     || '',
    wazuhApiPassword: row.wazuh_api_password || '',
    createdAt:        row.created_at,
  };
  if (includePassword) user.passwordHash = row.password_hash;
  return user;
}

/* ── Find user by email ── */
async function findByEmail(email, includePassword = false) {
  const cols = includePassword
    ? 'id, full_name, email, password_hash, organization, wazuh_ip, wazuh_indexer_ip, wazuh_user, wazuh_password, wazuh_api_user, wazuh_api_password, created_at'
    : 'id, full_name, email, organization, wazuh_ip, wazuh_indexer_ip, wazuh_user, wazuh_password, wazuh_api_user, wazuh_api_password, created_at';

  const [rows] = await getDb._pool.execute(
    `SELECT ${cols} FROM users WHERE email = ?`,
    [email.toLowerCase()]
  );
  if (rows.length === 0) return null;
  return mapRow(rows[0], includePassword);
}

/* ── Find user by ID ── */
async function findById(id) {
  const [rows] = await getDb._pool.execute(
    `SELECT id, full_name, email, organization, wazuh_ip, wazuh_indexer_ip, wazuh_user, wazuh_password, wazuh_api_user, wazuh_api_password, created_at
     FROM users WHERE id = ?`,
    [id]
  );
  if (rows.length === 0) return null;
  return mapRow(rows[0]);
}

/* ── Create a new user ── */
async function createUser({ fullName, email, password, organization = '', wazuhIp = '', wazuhIndexerIp = '', wazuhUser = '', wazuhPassword = '', wazuhApiUser = '', wazuhApiPassword = '' }) {
  const salt         = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const [result] = await getDb._pool.execute(
    `INSERT INTO users (full_name, email, password_hash, organization, wazuh_ip, wazuh_indexer_ip, wazuh_user, wazuh_password, wazuh_api_user, wazuh_api_password)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [fullName, email.toLowerCase(), passwordHash, organization, wazuhIp, wazuhIndexerIp, wazuhUser, wazuhPassword, wazuhApiUser, wazuhApiPassword]
  );
  return await findById(result.insertId);
}

/* ── Compare plain password against stored hash ── */
async function comparePassword(plainPassword, passwordHash) {
  return bcrypt.compare(plainPassword, passwordHash);
}

/* ── Update Wazuh connection credentials ── */
async function updateWazuhCreds(id, { wazuhIp, wazuhIndexerIp, wazuhUser, wazuhPassword, wazuhApiUser, wazuhApiPassword }) {
  await getDb._pool.execute(
    `UPDATE users SET wazuh_ip=?, wazuh_indexer_ip=?, wazuh_user=?, wazuh_password=?, wazuh_api_user=?, wazuh_api_password=? WHERE id=?`,
    [wazuhIp, wazuhIndexerIp || '', wazuhUser, wazuhPassword, wazuhApiUser, wazuhApiPassword, id]
  );
  return findById(id);
}

module.exports = { findByEmail, findById, createUser, comparePassword, updateWazuhCreds, getDb };
