/* ========================================
   WAZUHBOT — Main Application
   ======================================== */

import { initTheme }    from './theme.js';
import { initSettings } from './settings.js';

/* ── State ── */
let chats = [];          // { id, title, messages: [{ role, content, timestamp }] }
let activeChatId = null;

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

/* ── Simulated responses ── */
const RESPONSES = [
  "Wazuh is an open-source security platform that provides unified XDR and SIEM protection. It helps organizations detect threats, integrity monitoring, incident response, and compliance.\n\nHere's what I can help you with:\n\n• **Threat Detection** — Configure rules and decoders\n• **Agent Management** — Deploy and monitor agents\n• **Log Analysis** — Parse and correlate security events\n• **Compliance** — PCI DSS, HIPAA, GDPR reporting\n\nWhat would you like to know more about?",

  "To install a Wazuh agent on Ubuntu, follow these steps:\n\n**1. Import the GPG key:**\n```\ncurl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import\n```\n\n**2. Add the repository:**\n```\necho \"deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\" | tee /etc/apt/sources.list.d/wazuh.list\n```\n\n**3. Install the agent:**\n```\napt-get update && apt-get install wazuh-agent\n```\n\n**4. Register with your manager:**\nEdit `/var/ossec/etc/ossec.conf` and set the manager IP, then restart the service.\n\nWould you like me to walk you through the configuration in detail?",

  "Here are some commonly used Wazuh rules for threat detection:\n\n| Rule ID | Description | Level |\n|---------|------------|-------|\n| 5710 | SSH login attempt | 5 |\n| 5712 | SSH brute force | 10 |\n| 550 | Integrity checksum changed | 7 |\n| 554 | File added to the system | 5 |\n| 80790 | Windows audit failure | 5 |\n\nYou can customize these rules by creating local rules in `/var/ossec/etc/rules/local_rules.xml`.\n\nNeed help writing a custom rule for a specific use case?",

  "I'd be happy to help you analyze a security alert! To get started, I'll need a few pieces of information:\n\n1. **Alert Rule ID** — The specific Wazuh rule that triggered\n2. **Agent Name/ID** — Which endpoint generated the alert\n3. **Timestamp** — When the alert occurred\n4. **Full log** — The raw log data if available\n\nIn general, here's the analysis workflow I follow:\n\n• **Contextualize** — Understand what the rule detects\n• **Correlate** — Look for related events in the same timeframe\n• **Assess** — Determine if it's true positive or false positive\n• **Respond** — Recommend containment or tuning actions\n\nPaste the alert details and I'll analyze them for you!",

  "Great question! Let me explain the key differences between Wazuh SIEM and traditional SIEM solutions:\n\n**Wazuh Advantages:**\n- 🔓 **Open Source** — No licensing costs\n- 📊 **Unified Platform** — XDR + SIEM in one\n- 🔄 **Active Response** — Automated threat remediation\n- 📱 **Endpoint Visibility** — Lightweight agents on every host\n\n**Architecture Overview:**\nWazuh uses a manager-agent model. The **Wazuh Manager** receives and processes events from **Wazuh Agents** installed on monitored endpoints. Data is indexed in **Wazuh Indexer** (OpenSearch-based) and visualized through the **Wazuh Dashboard**.\n\nShall I dive deeper into any specific component?"
];

/* ── Boot ── */
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initSettings({ onDeleteAll: deleteAllChats });
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
  if (!text) return;

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

  // Simulate assistant response
  simulateResponse(chat);
}

function simulateResponse(chat) {
  // Show typing indicator
  appendTypingIndicator();
  scrollToBottom();

  const delay = 800 + Math.random() * 1200;
  setTimeout(() => {
    removeTypingIndicator();

    const responseText = RESPONSES[Math.floor(Math.random() * RESPONSES.length)];
    chat.messages.push({
      role: 'assistant',
      content: responseText,
      timestamp: Date.now(),
    });

    renderMessages();
    scrollToBottom();
    saveChats();
  }, delay);
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
      <button class="suggestion-card" data-prompt="Explain what Wazuh is and how it works">
        <div class="suggestion-icon">🛡️</div>
        <div class="suggestion-text">Explain what Wazuh is and how it works</div>
      </button>
      <button class="suggestion-card" data-prompt="How do I set up a Wazuh agent on Ubuntu?">
        <div class="suggestion-icon">🐧</div>
        <div class="suggestion-text">How do I set up a Wazuh agent on Ubuntu?</div>
      </button>
      <button class="suggestion-card" data-prompt="Show me common Wazuh rules for detecting threats">
        <div class="suggestion-icon">📋</div>
        <div class="suggestion-text">Show me common Wazuh rules for detecting threats</div>
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
    row.innerHTML = `
      <div class="message-avatar assistant-avatar">
        <img src="/logo.png" alt="WazuhBot" />
      </div>
      <div class="message-content">
        <div class="message-bubble">${formatMarkdown(msg.content)}</div>
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
