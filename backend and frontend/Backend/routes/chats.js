const express        = require('express');
const authMiddleware = require('../middleware/auth');
const { getDb }      = require('../models/User');

const router = express.Router();
router.use(authMiddleware);

/* GET /api/chats — list conversations for the authenticated user */
router.get('/', async (req, res) => {
  try {
    const db = getDb();
    const [rows] = await db.execute(
      `SELECT id, title, created_at, updated_at
       FROM conversations WHERE user_id = ? ORDER BY updated_at DESC`,
      [req.user.id]
    );
    res.json({ chats: rows });
  } catch (err) {
    console.error('List chats error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

/* POST /api/chats — create a new conversation */
router.post('/', async (req, res) => {
  const { id, title } = req.body;
  if (!id) return res.status(400).json({ message: 'id is required.' });
  try {
    const db = getDb();
    await db.execute(
      `INSERT INTO conversations (id, user_id, title) VALUES (?, ?, ?)`,
      [id, req.user.id, title || 'New Chat']
    );
    res.status(201).json({ message: 'Chat created.' });
  } catch (err) {
    if (err.errno === 1062) return res.status(409).json({ message: 'Chat already exists.' });
    console.error('Create chat error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

/* PUT /api/chats/:id — update conversation title */
router.put('/:id', async (req, res) => {
  const { title } = req.body;
  try {
    const db = getDb();
    await db.execute(
      `UPDATE conversations SET title = ?, updated_at = NOW() WHERE id = ? AND user_id = ?`,
      [title, req.params.id, req.user.id]
    );
    res.json({ message: 'Updated.' });
  } catch (err) {
    console.error('Update chat error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

/* DELETE /api/chats — delete ALL conversations for the user */
router.delete('/', async (req, res) => {
  try {
    const db = getDb();
    await db.execute(`DELETE FROM conversations WHERE user_id = ?`, [req.user.id]);
    res.json({ message: 'All chats deleted.' });
  } catch (err) {
    console.error('Delete all chats error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

/* DELETE /api/chats/:id — delete a single conversation */
router.delete('/:id', async (req, res) => {
  try {
    const db = getDb();
    await db.execute(
      `DELETE FROM conversations WHERE id = ? AND user_id = ?`,
      [req.params.id, req.user.id]
    );
    res.json({ message: 'Deleted.' });
  } catch (err) {
    console.error('Delete chat error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

/* GET /api/chats/:id/messages — get all messages for a conversation */
router.get('/:id/messages', async (req, res) => {
  try {
    const db = getDb();
    const [conv] = await db.execute(
      `SELECT id FROM conversations WHERE id = ? AND user_id = ?`,
      [req.params.id, req.user.id]
    );
    if (conv.length === 0) return res.status(404).json({ message: 'Chat not found.' });

    const [rows] = await db.execute(
      `SELECT role, content, tool_calls, sources, is_error, timestamp
       FROM messages WHERE conversation_id = ? ORDER BY id ASC`,
      [req.params.id]
    );

    const messages = rows.map(r => ({
      role:      r.role,
      content:   r.content,
      timestamp: r.timestamp,
      toolCalls: r.tool_calls ? JSON.parse(r.tool_calls) : [],
      sources:   r.sources    ? JSON.parse(r.sources)    : [],
      isError:   !!r.is_error,
    }));

    res.json({ messages });
  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

/* POST /api/chats/:id/messages — append a message to a conversation */
router.post('/:id/messages', async (req, res) => {
  const { role, content, toolCalls, sources, isError, timestamp } = req.body;
  if (!role || !content) return res.status(400).json({ message: 'role and content are required.' });

  try {
    const db = getDb();
    const [conv] = await db.execute(
      `SELECT id FROM conversations WHERE id = ? AND user_id = ?`,
      [req.params.id, req.user.id]
    );
    if (conv.length === 0) return res.status(404).json({ message: 'Chat not found.' });

    await db.execute(
      `INSERT INTO messages (conversation_id, role, content, tool_calls, sources, is_error, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        req.params.id,
        role,
        content,
        toolCalls && toolCalls.length ? JSON.stringify(toolCalls) : null,
        sources   && sources.length   ? JSON.stringify(sources)   : null,
        isError ? 1 : 0,
        timestamp || Date.now(),
      ]
    );

    await db.execute(
      `UPDATE conversations SET updated_at = NOW() WHERE id = ?`,
      [req.params.id]
    );

    res.status(201).json({ message: 'Message saved.' });
  } catch (err) {
    console.error('Save message error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

module.exports = router;
