const tokenKey = "secureaccessai_demo_token";

const messageBox = document.getElementById("message-box");
const responseBox = document.getElementById("response-box");
const usersBox = document.getElementById("users-box");
const tokenPreview = document.getElementById("token-preview");
const sessionStatus = document.getElementById("session-status");
const challengeInput = document.getElementById("challenge-id");
const loginForm = document.getElementById("login-form");
const demoAdminEmail = document.body.dataset.demoAdminEmail || "";
const demoAdminPassword = document.body.dataset.demoAdminPassword || "";

function getToken() {
  return localStorage.getItem(tokenKey) || "";
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
  sessionStatus.textContent = token ? "Logged in" : "Logged out";
  tokenPreview.textContent = token ? `${token.slice(0, 48)}...` : "No token";
}

function showMessage(text) {
  messageBox.textContent = text;
}

function showResponse(payload) {
  responseBox.textContent = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
}

function showUsers(payload) {
  usersBox.textContent = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
}

function setLoginFields(email, password) {
  loginForm.elements.email.value = email;
  loginForm.elements.password.value = password;
}

async function request(path, {method = "GET", body = null, auth = false} = {}) {
  const headers = {};
  if (body) {
    headers["Content-Type"] = "application/json";
  }
  if (auth && getToken()) {
    headers["Authorization"] = `Bearer ${getToken()}`;
  }

  const response = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });

  const data = await response.json().catch(() => ({error: "Invalid JSON response"}));
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
    const data = await request("/api/auth/register", {method: "POST", body: payload});
    showMessage("Register succeeded. You can now request a login code.");
    showResponse(data);
  } catch (error) {
    showMessage(`Register failed (${error.status || "error"}).`);
    showResponse(error.data || error);
  }
}

async function loginWithPayload(payload) {
  try {
    const data = await request("/api/auth/login", {method: "POST", body: payload});
    if (data.challenge_id) {
      challengeInput.value = data.challenge_id;
    }
    if (data.mfa_required) {
      const demoCode = data.demo_code ? ` Demo code: ${data.demo_code}` : "";
      showMessage(`Login code issued. Verify the one-time code to finish sign-in.${demoCode}`);
    } else if (data.access_token) {
      setToken(data.access_token);
      showMessage("Login succeeded.");
    }
    showResponse(data);
  } catch (error) {
    showMessage(`Login failed (${error.status || "error"}).`);
    showResponse(error.data || error);
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const payload = Object.fromEntries(form.entries());
  await loginWithPayload(payload);
}

async function handleVerifyCode(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const payload = Object.fromEntries(form.entries());
  try {
    const data = await request("/api/auth/verify-code", {method: "POST", body: payload});
    setToken(data.access_token);
    showMessage("Verification succeeded. Session token issued.");
    showResponse(data);
  } catch (error) {
    showMessage(`Verification failed (${error.status || "error"}).`);
    showResponse(error.data || error);
  }
}

async function handleAssignRole(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const payload = Object.fromEntries(form.entries());
  try {
    const data = await request("/api/rbac/assign-role", {method: "POST", body: payload, auth: true});
    showMessage("Role assignment succeeded.");
    showResponse(data);
  } catch (error) {
    showMessage(`Role assignment failed (${error.status || "error"}).`);
    showResponse(error.data || error);
  }
}

async function loadUsers() {
  try {
    const data = await request("/api/admin/users", {method: "GET", auth: true});
    showMessage("Loaded users.");
    showResponse(data);
    showUsers(data);
  } catch (error) {
    showMessage(`Loading users failed (${error.status || "error"}).`);
    showResponse(error.data || error);
    showUsers(error.data || error);
  }
}

async function handleDeleteUser(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const userId = form.get("user_id");
  try {
    const data = await request(`/api/admin/users/${userId}`, {method: "DELETE", auth: true});
    showMessage("User deletion succeeded.");
    showResponse(data);
    await loadUsers();
  } catch (error) {
    showMessage(`User deletion failed (${error.status || "error"}).`);
    showResponse(error.data || error);
  }
}

async function runAction(action) {
  const routes = {
    me: ["/api/auth/me", "GET"],
    dashboard: ["/api/admin/dashboard", "GET"],
    users: ["/api/admin/users", "GET"],
    "security-events": ["/api/admin/security-events", "GET"],
    "audit-logs": ["/api/admin/audit-logs", "GET"],
    "risk-summary": ["/api/admin/risk-summary", "GET"],
  };

  if (action === "logout") {
    try {
      const data = await request("/api/auth/logout", {method: "POST", auth: true});
      setToken("");
      showMessage("Logged out.");
      showResponse(data);
    } catch (error) {
      showMessage(`Logout failed (${error.status || "error"}).`);
      showResponse(error.data || error);
    }
    return;
  }

  if (action === "users") {
    await loadUsers();
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
    showMessage(`Request failed for ${action} (${error.status || "error"}).`);
    showResponse(error.data || error);
  }
}

function wireDemoLoginButtons() {
  const fillButton = document.getElementById("fill-demo-login");
  const requestButton = document.getElementById("request-demo-login");

  if (fillButton) {
    fillButton.addEventListener("click", () => {
      setLoginFields(demoAdminEmail, demoAdminPassword);
      showMessage("Demo admin credentials copied into the login form.");
    });
  }

  if (requestButton) {
    requestButton.addEventListener("click", async () => {
      setLoginFields(demoAdminEmail, demoAdminPassword);
      await loginWithPayload({email: demoAdminEmail, password: demoAdminPassword});
    });
  }
}

document.getElementById("register-form").addEventListener("submit", handleRegister);
document.getElementById("login-form").addEventListener("submit", handleLogin);
document.getElementById("verify-form").addEventListener("submit", handleVerifyCode);
document.getElementById("role-form").addEventListener("submit", handleAssignRole);
document.getElementById("delete-user-form").addEventListener("submit", handleDeleteUser);
document.querySelectorAll("[data-action]").forEach((button) => {
  button.addEventListener("click", () => runAction(button.dataset.action));
});

wireDemoLoginButtons();
syncSessionView();
