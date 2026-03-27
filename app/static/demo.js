const tokenKey = "secureaccessai_demo_token";

const authShell = document.getElementById("auth-shell");
const dashboardShell = document.getElementById("dashboard-shell");
const globalStatusChip = document.getElementById("global-status-chip");
const messageBox = document.getElementById("message-box");
const responseBox = document.getElementById("response-box");
const usersBox = document.getElementById("users-box");
const systemSummaryBox = document.getElementById("system-summary-box");
const currentUserBox = document.getElementById("current-user-box");
const tokenPreview = document.getElementById("token-preview");
const sessionStatus = document.getElementById("session-status");
const challengeInput = document.getElementById("challenge-id");
const loginForm = document.getElementById("login-form");
const pageMode = document.body.dataset.pageMode || "demo";
const demoAdminEmail = document.body.dataset.demoAdminEmail || "";
const demoAdminPassword = document.body.dataset.demoAdminPassword || "";

const metricUserCount = document.getElementById("metric-user-count");
const metricSecurityEventCount = document.getElementById("metric-security-event-count");
const metricAuditLogCount = document.getElementById("metric-audit-log-count");
const metricHighRiskCount = document.getElementById("metric-high-risk-count");

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
  const loggedIn = Boolean(token);
  if (!loggedIn && pageMode === "dashboard") {
    window.location.replace("/demo");
    return;
  }
  sessionStatus.textContent = loggedIn ? "Logged in" : "Logged out";
  tokenPreview.textContent = loggedIn ? `${token.slice(0, 48)}...` : "No token";
  authShell.classList.toggle("hidden", loggedIn);
  dashboardShell.classList.toggle("hidden", !loggedIn);
  globalStatusChip.textContent = loggedIn ? "Dashboard active" : "Ready for demo";
}

function goToDashboard() {
  if (window.location.pathname !== "/dashboard") {
    window.location.assign("/dashboard");
  }
}

function goToDemo() {
  if (window.location.pathname !== "/demo") {
    window.location.assign("/demo");
  }
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

function showSystemSummary(payload) {
  systemSummaryBox.textContent = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
}

function showCurrentUser(payload) {
  currentUserBox.textContent = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
}

function setLoginFields(email, password) {
  loginForm.elements.email.value = email;
  loginForm.elements.password.value = password;
}

function updateDashboardMetrics(usersPayload, dashboardPayload) {
  const users = usersPayload?.users || [];
  const systemSummary = dashboardPayload?.system_summary || {};
  const riskUsers = dashboardPayload?.risk_summary?.users || [];
  metricUserCount.textContent = String(users.length);
  metricSecurityEventCount.textContent = String(systemSummary.security_event_count || 0);
  metricAuditLogCount.textContent = String(systemSummary.audit_log_count || 0);
  metricHighRiskCount.textContent = String(riskUsers.filter((user) => user.risk_level === "high").length);
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
      goToDashboard();
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
    if (pageMode === "dashboard") {
      await bootstrapDashboard();
      showMessage("Verification succeeded. Dashboard loaded.");
    } else {
      showMessage("Verification succeeded. Redirecting to dashboard.");
      goToDashboard();
      return;
    }
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
    await bootstrapDashboard();
  } catch (error) {
    showMessage(`Role assignment failed (${error.status || "error"}).`);
    showResponse(error.data || error);
  }
}

async function loadUsers() {
  const data = await request("/api/admin/users", {method: "GET", auth: true});
  showUsers(data);
  return data;
}

async function loadMe() {
  const data = await request("/api/auth/me", {method: "GET", auth: true});
  showCurrentUser(data);
  return data;
}

async function loadDashboardOverview() {
  const data = await request("/api/admin/dashboard", {method: "GET", auth: true});
  showSystemSummary(data);
  return data;
}

async function bootstrapDashboard() {
  try {
    const [meData, dashboardData, usersData] = await Promise.all([
      loadMe(),
      loadDashboardOverview(),
      loadUsers(),
    ]);
    updateDashboardMetrics(usersData, dashboardData);
    showMessage(`Dashboard ready for ${meData.email}.`);
  } catch (error) {
    if (error.status === 401) {
      setToken("");
      showCurrentUser("Session expired.");
      showUsers("Load users to view masked email, roles, and recent IP information.");
      showSystemSummary("Dashboard summary not loaded yet.");
      showMessage("Session expired. Please log in again.");
      showResponse(error.data || error);
      return;
    }
    showMessage(`Dashboard load failed (${error.status || "error"}).`);
    showResponse(error.data || error);
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
    await bootstrapDashboard();
  } catch (error) {
    showMessage(`User deletion failed (${error.status || "error"}).`);
    showResponse(error.data || error);
  }
}

async function runAction(action) {
  if (action === "switch-account") {
    setToken("");
    showCurrentUser("No user loaded.");
    showUsers("Load users to view masked email, roles, and recent IP information.");
    showSystemSummary("Dashboard summary not loaded yet.");
    updateDashboardMetrics({users: []}, {system_summary: {}, risk_summary: {users: []}});
    showMessage("Session cleared. You can request a new login code.");
    showResponse("Switched back to login.");
    goToDemo();
    return;
  }

  if (action === "logout") {
    try {
      const data = await request("/api/auth/logout", {method: "POST", auth: true});
      setToken("");
      showCurrentUser("No user loaded.");
      showUsers("Load users to view masked email, roles, and recent IP information.");
      showSystemSummary("Dashboard summary not loaded yet.");
      updateDashboardMetrics({users: []}, {system_summary: {}, risk_summary: {users: []}});
      showMessage("Logged out.");
      showResponse(data);
      goToDemo();
    } catch (error) {
      showMessage(`Logout failed (${error.status || "error"}).`);
      showResponse(error.data || error);
    }
    return;
  }

  try {
    let data;
    if (action === "me") {
      data = await loadMe();
    } else if (action === "dashboard") {
      data = await loadDashboardOverview();
      const usersData = await loadUsers();
      updateDashboardMetrics(usersData, data);
    } else if (action === "users") {
      data = await loadUsers();
    } else if (action === "security-events") {
      data = await request("/api/admin/security-events", {method: "GET", auth: true});
    } else if (action === "audit-logs") {
      data = await request("/api/admin/audit-logs", {method: "GET", auth: true});
    } else if (action === "risk-summary") {
      data = await request("/api/admin/risk-summary", {method: "GET", auth: true});
    }

    if (data) {
      showMessage(`Loaded ${action}.`);
      showResponse(data);
    }
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
if (getToken()) {
  if (pageMode === "demo") {
    goToDashboard();
  } else {
    bootstrapDashboard();
  }
}
