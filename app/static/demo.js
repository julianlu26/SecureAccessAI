const tokenKey = 'secureaccessai_demo_token';

const messageBox = document.getElementById('message-box');
const responseBox = document.getElementById('response-box');
const tokenPreview = document.getElementById('token-preview');
const sessionStatus = document.getElementById('session-status');

function getToken() {
  return localStorage.getItem(tokenKey) || '';
}

function setToken(token) {
  if (token) {
    localStorage.setItem(tokenKey, token);
  } else {
    localStorage.removeItem(tokenKey);
  }
  syncSessionView();
}

function syncSessionView() {
  const token = getToken();
  sessionStatus.textContent = token ? 'Logged in' : 'Logged out';
  tokenPreview.textContent = token ? `${token.slice(0, 48)}...` : 'No token';
}

function showMessage(text) {
  messageBox.textContent = text;
}

function showResponse(payload) {
  responseBox.textContent = typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2);
}

async function request(path, {method = 'GET', body = null, auth = false} = {}) {
  const headers = {};
  if (body) {
    headers['Content-Type'] = 'application/json';
  }
  if (auth && getToken()) {
    headers['Authorization'] = `Bearer ${getToken()}`;
  }

  const response = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });

  const data = await response.json().catch(() => ({error: 'Invalid JSON response'}));
  if (!response.ok) {
    throw {status: response.status, data};
  }
  return data;
}

async function handleRegister(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const payload = Object.fromEntries(form.entries());
  try {
    const data = await request('/api/auth/register', {method: 'POST', body: payload});
    showMessage('Register succeeded. You can now login.');
    showResponse(data);
  } catch (error) {
    showMessage(`Register failed (${error.status || 'error'}).`);
    showResponse(error.data || error);
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const payload = Object.fromEntries(form.entries());
  try {
    const data = await request('/api/auth/login', {method: 'POST', body: payload});
    setToken(data.access_token);
    showMessage('Login succeeded. Token stored in this browser.');
    showResponse(data);
  } catch (error) {
    showMessage(`Login failed (${error.status || 'error'}).`);
    showResponse(error.data || error);
  }
}

async function handleAssignRole(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const payload = Object.fromEntries(form.entries());
  try {
    const data = await request('/api/rbac/assign-role', {method: 'POST', body: payload, auth: true});
    showMessage('Role assignment succeeded.');
    showResponse(data);
  } catch (error) {
    showMessage(`Role assignment failed (${error.status || 'error'}).`);
    showResponse(error.data || error);
  }
}

async function runAction(action) {
  const routes = {
    me: ['/api/auth/me', 'GET'],
    dashboard: ['/api/admin/dashboard', 'GET'],
    'security-events': ['/api/admin/security-events', 'GET'],
    'audit-logs': ['/api/admin/audit-logs', 'GET'],
    'risk-summary': ['/api/admin/risk-summary', 'GET'],
  };

  if (action === 'logout') {
    try {
      const data = await request('/api/auth/logout', {method: 'POST', auth: true});
      setToken('');
      showMessage('Logged out.');
      showResponse(data);
    } catch (error) {
      showMessage(`Logout failed (${error.status || 'error'}).`);
      showResponse(error.data || error);
    }
    return;
  }

  const route = routes[action];
  if (!route) {
    return;
  }

  try {
    const data = await request(route[0], {method: route[1], auth: true});
    showMessage(`Loaded ${action}.`);
    showResponse(data);
  } catch (error) {
    showMessage(`Request failed for ${action} (${error.status || 'error'}).`);
    showResponse(error.data || error);
  }
}

document.getElementById('register-form').addEventListener('submit', handleRegister);
document.getElementById('login-form').addEventListener('submit', handleLogin);
document.getElementById('role-form').addEventListener('submit', handleAssignRole);
document.querySelectorAll('[data-action]').forEach((button) => {
  button.addEventListener('click', () => runAction(button.dataset.action));
});

syncSessionView();
