/* ========================================
   WAZUHBOT — Main Application
   ======================================== */

import { initTheme }    from './theme.js';
import { initSettings } from './settings.js';
import { initSentinel } from './sentinel.js';

/* ── State ── */
let chats = [];              // [{ id, title, messages: [] | null, created_at, updated_at }]
let activeChatId = null;
let isWaitingForResponse = false;

/* ── API Config ── */
const API_BASE = window.location.hostname === 'localhost'
  ? 'http://localhost:5000/api'
  : '/api';

/* ── DOM refs ── */
const chatList          = document.getElementById('chatList');
const chatMessages      = document.getElementById('chatMessages');
const chatInput         = document.getElementById('chatInput');
const sendBtn           = document.getElementById('sendBtn');
const newChatBtn        = document.getElementById('newChatBtn');
const sidebar           = document.getElementById('sidebar');
const sidebarToggle     = document.getElementById('sidebarToggleBtn');
const sidebarClose      = document.getElementById('sidebarCloseBtn');
/* ── Confirmation prompt detection ── */
const CONFIRM_PATTERNS = [
  /reply\s+yes\s+to\s+execute/i,
  /reply\s+yes\s+to\s+proceed/i,
  /type\s+yes\s+to\s+execute/i,
  /say\s+yes\s+to\s+execute/i,
  /reply\s+yes\s+or\s+no/i,
  /reply\s+yes/i,
  /type\s+yes/i,
];

function containsConfirmationPrompt(text) {
  return CONFIRM_PATTERNS.some(p => p.test(text));
}

function appendApproveButton(row) {
  const content = row.querySelector('.message-content');
  const approveDiv = document.createElement('div');
  approveDiv.className = 'approve-action';
  approveDiv.innerHTML = `
    <button class="approve-btn">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12"/>
      </svg>
      Approve
    </button>
  `;
  content.appendChild(approveDiv);
  approveDiv.querySelector('.approve-btn').addEventListener('click', () => {
    approveDiv.remove();
    chatInput.value = 'Yes';
    chatInput.dispatchEvent(new Event('input'));
    handleSend();
  });
  scrollToBottom();
}

/* ── Boot ── */
document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('wazuhbot-token');
  if (!token) {
    window.location.href = '/login.html';
    return;
  }

  initTheme();
  initSettings({ onDeleteAll: deleteAllChats });
  initSentinel({ onClose: () => { renderSidebar(); renderMessages(); } });
  bindEvents();
  loadChats();
});

/* ── Auth helpers ── */
function authHeaders() {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${localStorage.getItem('wazuhbot-token')}`,
  };
}

function logout() {
  localStorage.removeItem('wazuhbot-token');
  localStorage.removeItem('wazuhbot-user');
  window.location.href = '/login.html';
}

/* ── API helpers ── */
async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { ...authHeaders(), ...options.headers },
  });
  if (res.status === 401) { logout(); return null; }
  return res;
}

async function apiLoadChats() {
  try {
    const res = await apiFetch('/chats/');
    if (!res || !res.ok) return [];
    const data = await res.json();
    return (data.chats || []).map(c => ({ ...c, messages: null }));
  } catch (err) {
    console.error('Failed to load chats:', err);
    return [];
  }
}

async function apiCreateChat(id, title) {
  const res = await apiFetch('/chats/', {
    method: 'POST',
    body: JSON.stringify({ id, title }),
  });
  if (res && !res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || 'Failed to create chat');
  }
}

async function apiLoadMessages(chatId) {
  try {
    const res = await apiFetch(`/chats/${chatId}/messages`);
    if (!res || !res.ok) return [];
    const data = await res.json();
    return data.messages || [];
  } catch (err) {
    console.error('Failed to load messages:', err);
    return [];
  }
}

async function apiSaveMessage(chatId, msg) {
  try {
    await apiFetch(`/chats/${chatId}/messages`, {
      method: 'POST',
      body: JSON.stringify({
        role:      msg.role,
        content:   msg.content,
        toolCalls: msg.toolCalls || [],
        sources:   msg.sources   || [],
        isError:   msg.isError   || false,
        timestamp: msg.timestamp || Date.now(),
      }),
    });
  } catch (err) {
    console.error('Failed to save message:', err);
  }
}

async function apiUpdateTitle(chatId, title) {
  try {
    await apiFetch(`/chats/${chatId}`, {
      method: 'PUT',
      body: JSON.stringify({ title }),
    });
  } catch (err) {
    console.error('Failed to update title:', err);
  }
}

async function apiDeleteChat(chatId) {
  try {
    await apiFetch(`/chats/${chatId}`, { method: 'DELETE' });
  } catch (err) {
    console.error('Failed to delete chat:', err);
  }
}

async function apiDeleteAllChats() {
  try {
    await apiFetch('/chats/', { method: 'DELETE' });
  } catch (err) {
    console.error('Failed to delete all chats:', err);
  }
}

/* ── Load chats from server ── */
async function loadChats() {
  chats = await apiLoadChats();

  // Restore last active chat from session, or fall back to first
  const savedId = sessionStorage.getItem('activeChatId');
  if (savedId && chats.find(c => c.id === savedId)) {
    activeChatId = savedId;
  } else if (chats.length > 0) {
    activeChatId = chats[0].id;
  }

  renderSidebar();

  if (activeChatId) {
    const active = getActiveChat();
    if (active && active.messages === null) {
      active.messages = await apiLoadMessages(activeChatId);
    }
  }

  renderMessages();
  scrollToBottom();
}

/* ── Event bindings ── */
function bindEvents() {
  sendBtn.addEventListener('click', handleSend);
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  });

  chatInput.addEventListener('input', () => {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 200) + 'px';
    sendBtn.classList.toggle('active', chatInput.value.trim().length > 0);
    sendBtn.disabled = chatInput.value.trim().length === 0;
  });

  newChatBtn.addEventListener('click', async () => {
    await createNewChat();
    closeSidebarMobile();
  });

  sidebarToggle.addEventListener('click', openSidebarMobile);
  sidebarClose.addEventListener('click', closeSidebarMobile);

  document.querySelectorAll('.suggestion-card').forEach(card => {
    card.addEventListener('click', () => {
      const prompt = card.dataset.prompt;
      if (prompt) {
        chatInput.value = prompt;
        chatInput.dispatchEvent(new Event('input'));
        handleSend();
      }
    });
  });

  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('sidebar-overlay')) closeSidebarMobile();
  });

  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);

}

/* ── Chat management ── */
async function createNewChat(switchTo = true) {
  const id    = 'chat-' + Date.now();
  const title = 'New Chat';
  const chat  = { id, title, messages: [] };
  chats.unshift(chat);

  // Persist to DB before allowing messages so foreign-key checks pass
  try { await apiCreateChat(id, title); } catch (e) { console.error(e); }

  if (switchTo) {
    activeChatId = id;
    sessionStorage.setItem('activeChatId', id);
    renderSidebar();
    renderMessages();
    chatInput.focus();
  }

  return chat;
}

async function switchChat(id) {
  activeChatId = id;
  sessionStorage.setItem('activeChatId', id);
  renderSidebar();

  const chat = getActiveChat();
  if (chat && chat.messages === null) {
    chatMessages.innerHTML = '<div class="messages-loading">Loading…</div>';
    chat.messages = await apiLoadMessages(id);
  }

  renderMessages();
  scrollToBottom();
  closeSidebarMobile();
}

function deleteChat(id) {
  chats = chats.filter(c => c.id !== id);
  if (activeChatId === id) {
    activeChatId = chats.length > 0 ? chats[0].id : null;
    sessionStorage.setItem('activeChatId', activeChatId || '');
  }
  apiDeleteChat(id);
  renderSidebar();
  renderMessages();
}

function deleteAllChats() {
  chats = [];
  activeChatId = null;
  sessionStorage.removeItem('activeChatId');
  apiDeleteAllChats();
  renderSidebar();
  renderMessages();
}

function getActiveChat() {
  return chats.find(c => c.id === activeChatId) || null;
}

/* ── Send ── */
async function handleSend() {
  const text = chatInput.value.trim();
  if (!text || isWaitingForResponse) return;

  let chat = getActiveChat();
  if (!chat) {
    chat = await createNewChat(true);
  }

  // Set title from first user message
  if (chat.messages.length === 0) {
    chat.title = text.length > 40 ? text.slice(0, 40) + '…' : text;
    apiUpdateTitle(chat.id, chat.title);
    renderSidebar();
  }

  const userMsg = { role: 'user', content: text, timestamp: Date.now() };
  chat.messages.push(userMsg);
  apiSaveMessage(chat.id, userMsg);

  chatInput.value = '';
  chatInput.style.height = 'auto';
  sendBtn.classList.remove('active');
  sendBtn.disabled = true;

  renderMessages();
  scrollToBottom();

  sendToChatbot(chat, text);
}

/* ── API Call to Chatbot ── */
async function sendToChatbot(chat, userMessage) {
  isWaitingForResponse = true;
  appendTypingIndicator();
  scrollToBottom();

  const history = chat.messages
    .slice(0, -1)
    .filter(m => m.role === 'user' || m.role === 'assistant')
    .map(m => ({ role: m.role, content: m.content }));

  try {
    const token = localStorage.getItem('wazuhbot-token');
    const response = await fetch(`${API_BASE}/chat/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ message: userMessage, history, context: {} }),
    });

    removeTypingIndicator();

    if (response.status === 401) {
      logout();
      return;
    }

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || errData.details || `HTTP ${response.status}`);
    }

    const data = await response.json();

    const assistantMsg = {
      role:      'assistant',
      content:   data.response || 'No response received.',
      timestamp: Date.now(),
      toolCalls: data.tool_calls || [],
      sources:   data.sources   || [],
    };

    chat.messages.push(assistantMsg);
    apiSaveMessage(chat.id, assistantMsg);

    // Build the row with an empty bubble, then animate words in
    const row = createMessageRow({ ...assistantMsg, content: '​' });
    chatMessages.appendChild(row);
    scrollToBottom();

    const bubble = row.querySelector('.message-bubble');
    bubble.classList.add('typing-cursor');

    const words = assistantMsg.content.split(' ');
    let idx = 0;
    let plain = '';

    const timer = setInterval(() => {
      if (idx < words.length) {
        plain += (idx === 0 ? '' : ' ') + words[idx];
        bubble.textContent = plain;
        idx++;
        if (idx % 8 === 0) scrollToBottom();
      } else {
        clearInterval(timer);
        bubble.classList.remove('typing-cursor');
        bubble.innerHTML = formatMarkdown(assistantMsg.content);
        scrollToBottom();
        if (containsConfirmationPrompt(assistantMsg.content)) {
          appendApproveButton(row);
        }
      }
    }, 22);

  } catch (err) {
    removeTypingIndicator();
    console.error('Chatbot error:', err);

    const errorMsg = {
      role:      'assistant',
      content:   getChatbotErrorMessage(err.message),
      timestamp: Date.now(),
      isError:   true,
    };

    chat.messages.push(errorMsg);
    apiSaveMessage(chat.id, errorMsg);
    renderMessages();
    scrollToBottom();

  } finally {
    isWaitingForResponse = false;
  }
}

function getChatbotErrorMessage(errMsg) {
  if (errMsg.includes('unreachable') || errMsg.includes('Failed to fetch') || errMsg.includes('NetworkError')) {
    return `⚠️ **Chatbot service is not running.**\n\nTo start the chatbot, run:\n\`\`\`\ncd Backend/chatbot\npython chatbot_server.py\n\`\`\`\n\nMake sure Ollama is also running with the model pulled:\n\`\`\`\nollama pull qwen2.5:3b\n\`\`\``;
  }
  if (errMsg.includes('not installed') || errMsg.includes('not found')) {
    return `⚠️ **LLM model not found.**\n\nPlease pull the model:\n\`\`\`\nollama pull qwen2.5:3b\n\`\`\`\nThen restart the chatbot service.`;
  }
  return `⚠️ **Something went wrong:** ${errMsg}\n\nPlease check the backend logs and try again.`;
}

/* ── Rendering ── */
function renderSidebar() {
  if (chats.length === 0) {
    chatList.innerHTML = '<li class="empty-history">No conversations yet</li>';
    return;
  }

  chatList.innerHTML = chats.map(chat => `
    <li class="chat-list-item ${chat.id === activeChatId ? 'active' : ''}" data-id="${chat.id}">
      <a>
        <svg class="chat-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
        <span>${escapeHtml(chat.title)}</span>
      </a>
      <button class="btn-icon delete-chat-btn" title="Delete chat">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
      </button>
    </li>
  `).join('');

  chatList.querySelectorAll('.chat-list-item').forEach(li => {
    const id = li.dataset.id;
    li.querySelector('a').addEventListener('click', () => switchChat(id));
    li.querySelector('.delete-chat-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      deleteChat(id);
    });
  });
}

function renderMessages() {
  const chat = getActiveChat();

  if (!chat || chat.messages.length === 0) {
    chatMessages.innerHTML = '';
    chatMessages.appendChild(createWelcomeScreen());
    return;
  }

  chatMessages.innerHTML = '';
  chat.messages.forEach(msg => chatMessages.appendChild(createMessageRow(msg)));
}

function createWelcomeScreen() {
  const div = document.createElement('div');
  div.className = 'welcome-screen';
  div.id = 'welcomeScreen';
  div.innerHTML = `
    <div class="welcome-logo">
      <img src="/logo.png" alt="Wazuh" class="welcome-logo-img" />
    </div>
    <h1 class="welcome-title">How can I help you today?</h1>
    <div class="suggestion-cards">
      <button class="suggestion-card" data-prompt="Show me recent critical security alerts">
        <div class="suggestion-icon">🛡️</div>
        <div class="suggestion-text">Show me recent critical security alerts</div>
      </button>
      <button class="suggestion-card" data-prompt="Are there any brute force attacks happening right now?">
        <div class="suggestion-icon">🔐</div>
        <div class="suggestion-text">Are there any brute force attacks right now?</div>
      </button>
      <button class="suggestion-card" data-prompt="Give me a summary of active agents and their status">
        <div class="suggestion-icon">📡</div>
        <div class="suggestion-text">Summary of active agents and their status</div>
      </button>
      <button class="suggestion-card" data-prompt="Help me analyze a security alert from my Wazuh dashboard">
        <div class="suggestion-icon">🔍</div>
        <div class="suggestion-text">Help me analyze a security alert from my dashboard</div>
      </button>
    </div>
  `;

  div.querySelectorAll('.suggestion-card').forEach(card => {
    card.addEventListener('click', () => {
      const prompt = card.dataset.prompt;
      if (prompt) {
        chatInput.value = prompt;
        chatInput.dispatchEvent(new Event('input'));
        handleSend();
      }
    });
  });

  return div;
}

function createMessageRow(msg) {
  const row = document.createElement('div');
  row.className = `message-row ${msg.role}`;

  if (msg.role === 'user') {
    row.innerHTML = `
      <div class="message-avatar user-avatar">U</div>
      <div class="message-content">
        <div class="message-bubble">${escapeHtml(msg.content)}</div>
      </div>
    `;
  } else {
    let toolCallsHtml = '';
    if (msg.toolCalls && msg.toolCalls.length > 0) {
      const toolItems = msg.toolCalls.map(tc => {
        const args = typeof tc.arguments === 'object'
          ? Object.entries(tc.arguments).map(([k, v]) => `${k}: ${v}`).join(', ')
          : '';
        return `<div class="tool-call-item">
          <span class="tool-call-icon">🔧</span>
          <span class="tool-call-name">${escapeHtml(tc.tool)}</span>
          ${args ? `<span class="tool-call-args">(${escapeHtml(args)})</span>` : ''}
        </div>`;
      }).join('');

      toolCallsHtml = `
        <div class="tool-calls-indicator">
          <div class="tool-calls-header">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
            <span>Tools Used</span>
          </div>
          ${toolItems}
        </div>
      `;
    }

    let sourcesHtml = '';
    if (msg.sources && msg.sources.length > 0) {
      sourcesHtml = `
        <div class="sources-indicator">
          <span class="sources-label">📚 Sources:</span>
          ${msg.sources.map(s => `<span class="source-tag">${escapeHtml(s)}</span>`).join('')}
        </div>
      `;
    }

    row.innerHTML = `
      <div class="message-avatar assistant-avatar">
        <img src="/logo.png" alt="WazuhBot" />
      </div>
      <div class="message-content">
        ${toolCallsHtml}
        <div class="message-bubble ${msg.isError ? 'message-error' : ''}">${formatMarkdown(msg.content)}</div>
        ${sourcesHtml}
      </div>
    `;
  }

  return row;
}

/* ── Typing indicator ── */
function appendTypingIndicator() {
  const row = document.createElement('div');
  row.className = 'message-row assistant';
  row.id = 'typingRow';
  row.innerHTML = `
    <div class="message-avatar assistant-avatar">
      <img src="/logo.png" alt="WazuhBot" />
    </div>
    <div class="message-content">
      <div class="typing-indicator">
        <div class="typing-label">Thinking</div>
        <div class="dot"></div>
        <div class="dot"></div>
        <div class="dot"></div>
      </div>
    </div>
  `;
  chatMessages.appendChild(row);
}

function removeTypingIndicator() {
  const el = document.getElementById('typingRow');
  if (el) el.remove();
}

/* ── Sidebar mobile ── */
function openSidebarMobile() {
  sidebar.classList.add('open');
  getOrCreateOverlay().classList.add('active');
}

function closeSidebarMobile() {
  sidebar.classList.remove('open');
  const overlay = document.querySelector('.sidebar-overlay');
  if (overlay) overlay.classList.remove('active');
}

function getOrCreateOverlay() {
  let overlay = document.querySelector('.sidebar-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.className = 'sidebar-overlay';
    document.body.appendChild(overlay);
    overlay.addEventListener('click', closeSidebarMobile);
  }
  return overlay;
}

/* ── Helpers ── */
function scrollToBottom() {
  requestAnimationFrame(() => {
    chatMessages.scrollTop = chatMessages.scrollHeight;
  });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function formatMarkdown(text) {
  let html = escapeHtml(text);

  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_m, _lang, code) => {
    return `<pre class="code-block"><code>${code.trim()}</code></pre>`;
  });

  html = html.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, '<em>$1</em>');
  html = html.replace(/^[•\-] (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>');
  html = html.replace(/<\/ul>\s*<ul>/g, '');
  html = html.replace(/^\d+\.\s+(.+)$/gm, '<li>$1</li>');

  html = html.replace(/((?:\|.+\|\n?)+)/g, (match) => {
    const rows = match.trim().split('\n').filter(r => !r.match(/^\|[\s\-|]+\|$/));
    if (rows.length === 0) return match;
    const header = rows[0];
    const body   = rows.slice(1);
    const parseRow = (r) => r.split('|').filter(c => c.trim()).map(c => c.trim());

    let table = '<table class="md-table"><thead><tr>';
    parseRow(header).forEach(c => { table += `<th>${c}</th>`; });
    table += '</tr></thead><tbody>';
    body.forEach(r => {
      table += '<tr>';
      parseRow(r).forEach(c => { table += `<td>${c}</td>`; });
      table += '</tr>';
    });
    table += '</tbody></table>';
    return table;
  });

  html = html.replace(/\n/g, '<br>');
  return html;
}
