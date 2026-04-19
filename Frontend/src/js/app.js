/* ========================================
   WAZUHBOT — Main Application
   ======================================== */

import { initTheme }    from './theme.js';
import { initSettings } from './settings.js';
import { initSentinel } from './sentinel.js';

/* ── State ── */
let chats = [];          // { id, title, messages: [{ role, content, timestamp, toolCalls?, sources? }] }
let activeChatId = null;
let isWaitingForResponse = false;

/* ── API Config ── */
const API_BASE = window.location.hostname === 'localhost'
  ? 'http://localhost:5000/api'
  : '/api';

/* ── DOM refs ── */
const chatList       = document.getElementById('chatList');
const chatMessages   = document.getElementById('chatMessages');
const welcomeScreen  = document.getElementById('welcomeScreen');
const chatInput      = document.getElementById('chatInput');
const sendBtn        = document.getElementById('sendBtn');
const newChatBtn     = document.getElementById('newChatBtn');
const sidebar        = document.getElementById('sidebar');
const sidebarToggle  = document.getElementById('sidebarToggleBtn');
const sidebarClose   = document.getElementById('sidebarCloseBtn');

/* ── Boot ── */
document.addEventListener('DOMContentLoaded', () => {
  // Auth guard — redirect to login if no token
  const token = localStorage.getItem('wazuhbot-token');
  if (!token) {
    window.location.href = '/login.html';
    return;
  }

  initTheme();
  initSettings({ onDeleteAll: deleteAllChats });
  initSentinel();
  loadChats();
  bindEvents();
});

/* ── Event bindings ── */
function bindEvents() {
  // Send message
  sendBtn.addEventListener('click', handleSend);
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  });

  // Auto-resize textarea
  chatInput.addEventListener('input', () => {
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 200) + 'px';
    sendBtn.classList.toggle('active', chatInput.value.trim().length > 0);
    sendBtn.disabled = chatInput.value.trim().length === 0;
  });

  // New chat
  newChatBtn.addEventListener('click', () => {
    createNewChat();
    closeSidebarMobile();
  });

  // Sidebar toggle (mobile)
  sidebarToggle.addEventListener('click', openSidebarMobile);
  sidebarClose.addEventListener('click', closeSidebarMobile);

  // Suggestion cards
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

  // Overlay click to close sidebar
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('sidebar-overlay')) {
      closeSidebarMobile();
    }
  });
}

/* ── Chat management ── */
function createNewChat(switchTo = true) {
  const id = 'chat-' + Date.now();
  const chat = {
    id,
    title: 'New Chat',
    messages: [],
  };
  chats.unshift(chat);
  if (switchTo) {
    activeChatId = id;
    renderSidebar();
    renderMessages();
    chatInput.focus();
  }
  saveChats();
  return chat;
}

function switchChat(id) {
  activeChatId = id;
  renderSidebar();
  renderMessages();
  closeSidebarMobile();
}

function deleteChat(id) {
  chats = chats.filter(c => c.id !== id);
  if (activeChatId === id) {
    activeChatId = chats.length > 0 ? chats[0].id : null;
  }
  renderSidebar();
  renderMessages();
  saveChats();
}

function deleteAllChats() {
  chats = [];
  activeChatId = null;
  renderSidebar();
  renderMessages();
  saveChats();
}

function getActiveChat() {
  return chats.find(c => c.id === activeChatId) || null;
}

/* ── Persistence ── */
function saveChats() {
  localStorage.setItem('wazuhbot-chats', JSON.stringify(chats));
}

function loadChats() {
  try {
    const stored = JSON.parse(localStorage.getItem('wazuhbot-chats'));
    if (Array.isArray(stored) && stored.length > 0) {
      chats = stored;
      activeChatId = chats[0].id;
    }
  } catch {}
  renderSidebar();
  renderMessages();
}

/* ── Send ── */
function handleSend() {
  const text = chatInput.value.trim();
  if (!text || isWaitingForResponse) return;

  // If no chat exists yet, create one
  if (!activeChatId) {
    createNewChat(true);
  }

  const chat = getActiveChat();
  if (!chat) return;

  // Update title from first message
  if (chat.messages.length === 0) {
    chat.title = text.length > 40 ? text.slice(0, 40) + '…' : text;
    renderSidebar();
  }

  // Add user message
  chat.messages.push({
    role: 'user',
    content: text,
    timestamp: Date.now(),
  });

  // Clear input
  chatInput.value = '';
  chatInput.style.height = 'auto';
  sendBtn.classList.remove('active');
  sendBtn.disabled = true;

  renderMessages();
  scrollToBottom();
  saveChats();

  // Call real chatbot API
  sendToChatbot(chat, text);
}

/* ── API Call to Chatbot ── */
async function sendToChatbot(chat, userMessage) {
  isWaitingForResponse = true;
  appendTypingIndicator();
  scrollToBottom();

  // Build history for the API (exclude the message we just sent — it goes as 'message')
  const history = chat.messages
    .slice(0, -1)  // exclude the last user message (sent separately)
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
      body: JSON.stringify({
        message: userMessage,
        history: history,
        context: {},
      }),
    });

    removeTypingIndicator();

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || errData.details || `HTTP ${response.status}`);
    }

    const data = await response.json();

    // Add assistant response to chat
    chat.messages.push({
      role: 'assistant',
      content: data.response || 'No response received.',
      timestamp: Date.now(),
      toolCalls: data.tool_calls || [],
      sources: data.sources || [],
    });

    renderMessages();
    scrollToBottom();
    saveChats();

  } catch (err) {
    removeTypingIndicator();
    console.error('Chatbot error:', err);

    // Add error message as assistant response
    const errorContent = getChatbotErrorMessage(err.message);

    chat.messages.push({
      role: 'assistant',
      content: errorContent,
      timestamp: Date.now(),
      isError: true,
    });

    renderMessages();
    scrollToBottom();
    saveChats();

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

  // Bind click events
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
    // Show welcome screen
    chatMessages.innerHTML = '';
    chatMessages.appendChild(createWelcomeScreen());
    return;
  }

  // Hide welcome, show messages
  chatMessages.innerHTML = '';
  chat.messages.forEach(msg => {
    chatMessages.appendChild(createMessageRow(msg));
  });
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

  // Bind suggestion cards
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
    // Build tool calls indicator
    let toolCallsHtml = '';
    if (msg.toolCalls && msg.toolCalls.length > 0) {
      const toolItems = msg.toolCalls.map(tc => {
        const args = typeof tc.arguments === 'object'
          ? Object.entries(tc.arguments).map(([k,v]) => `${k}: ${v}`).join(', ')
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

    // Build sources indicator
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

/**
 * Very lightweight markdown-ish formatting for assistant responses.
 */
function formatMarkdown(text) {
  let html = escapeHtml(text);

  // Code blocks ``` ... ```
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_m, _lang, code) => {
    return `<pre class="code-block"><code>${code.trim()}</code></pre>`;
  });

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');

  // Bold **text**
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

  // Italic *text*
  html = html.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, '<em>$1</em>');

  // Bullet points (• or -)
  html = html.replace(/^[•\-] (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>');
  // Clean up nested uls
  html = html.replace(/<\/ul>\s*<ul>/g, '');

  // Numbered lists
  html = html.replace(/^\d+\.\s+(.+)$/gm, '<li>$1</li>');

  // Tables (simple)
  html = html.replace(/((?:\|.+\|\n?)+)/g, (match) => {
    const rows = match.trim().split('\n').filter(r => !r.match(/^\|[\s\-|]+\|$/));
    if (rows.length === 0) return match;
    const header = rows[0];
    const body = rows.slice(1);
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

  // Line breaks
  html = html.replace(/\n/g, '<br>');

  return html;
}
