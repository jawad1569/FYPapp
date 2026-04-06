const oracledb = require('oracledb');
const bcrypt = require('bcryptjs');

/* ── Row mapper: Oracle uppercase keys → camelCase object ── */
function mapRow(row, includePassword = false) {
  const user = {
    _id:          row.ID,
    fullName:     row.FULL_NAME,
    email:        row.EMAIL,
    organization: row.ORGANIZATION || '',
    wazuhIp:      row.WAZUH_IP     || '',
    createdAt:    row.CREATED_AT,
  };
  if (includePassword) user.passwordHash = row.PASSWORD_HASH;
  return user;
}

/* ── Find user by email ── */
async function findByEmail(email, includePassword = false) {
  const cols = includePassword
    ? 'ID, FULL_NAME, EMAIL, PASSWORD_HASH, ORGANIZATION, WAZUH_IP, CREATED_AT'
    : 'ID, FULL_NAME, EMAIL, ORGANIZATION, WAZUH_IP, CREATED_AT';

  const conn = await oracledb.getConnection();
  try {
    const result = await conn.execute(
      `SELECT ${cols} FROM USERS WHERE EMAIL = :email`,
      { email: email.toLowerCase() },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    if (result.rows.length === 0) return null;
    return mapRow(result.rows[0], includePassword);
  } finally {
    await conn.close();
  }
}

/* ── Find user by ID ── */
async function findById(id) {
  const conn = await oracledb.getConnection();
  try {
    const result = await conn.execute(
      `SELECT ID, FULL_NAME, EMAIL, ORGANIZATION, WAZUH_IP, CREATED_AT
       FROM USERS WHERE ID = :id`,
      { id },
      { outFormat: oracledb.OUT_FORMAT_OBJECT }
    );
    if (result.rows.length === 0) return null;
    return mapRow(result.rows[0]);
  } finally {
    await conn.close();
  }
}

/* ── Create a new user ── */
async function createUser({ fullName, email, password, organization = '', wazuhIp = '' }) {
  const salt         = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const conn = await oracledb.getConnection();
  try {
    const result = await conn.execute(
      `INSERT INTO USERS (FULL_NAME, EMAIL, PASSWORD_HASH, ORGANIZATION, WAZUH_IP)
       VALUES (:fullName, :email, :passwordHash, :organization, :wazuhIp)
       RETURNING ID INTO :id`,
      {
        fullName,
        email:        email.toLowerCase(),
        passwordHash,
        organization,
        wazuhIp,
        id: { type: oracledb.NUMBER, dir: oracledb.BIND_OUT },
      },
      { autoCommit: true }
    );
    const newId = result.outBinds.id[0];
    return await findById(newId);
  } finally {
    await conn.close();
  }
}

/* ── Compare plain password against stored hash ── */
async function comparePassword(plainPassword, passwordHash) {
  return bcrypt.compare(plainPassword, passwordHash);
}

module.exports = { findByEmail, findById, createUser, comparePassword };
