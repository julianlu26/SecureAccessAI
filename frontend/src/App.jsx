import React, { useEffect, useMemo, useState } from 'react';

const bootstrap = window.SECUREACCESS_BOOTSTRAP || {};
const TOKEN_KEY = 'secureaccessai_console_token';
const LEGACY_TOKEN_KEY = 'secureaccessai_demo_token';

const NAV_ITEMS = [
  { id: 'resources', label: 'Resources' },
  { id: 'activity', label: 'Activity' },
  { id: 'settings', label: 'Settings' },
];

const RESOURCE_ITEMS = [
  { id: 'identity', label: 'Identity' },
  { id: 'threats', label: 'Threats' },
  { id: 'network', label: 'Network Security' },
];

function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY) || localStorage.getItem(LEGACY_TOKEN_KEY) || '';
}

function saveToken(token) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.removeItem(LEGACY_TOKEN_KEY);
  } else {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(LEGACY_TOKEN_KEY);
  }
}

async function apiRequest(path, { method = 'GET', body, token } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await response.json().catch(() => ({ error: 'Invalid JSON response' }));
  if (!response.ok) {
    throw { status: response.status, data: payload };
  }
  return payload;
}

function maskToken(token) {
  if (!token) return 'No token';
  return `${token.slice(0, 36)}...`;
}

function MetricCard({ label, value, hint, tone = 'default' }) {
  return (
    <article className={`metric-card metric-card--${tone}`}>
      <span className="metric-card__label">{label}</span>
      <strong className="metric-card__value">{value}</strong>
      <span className="metric-card__hint">{hint}</span>
    </article>
  );
}

function ActionButton({ children, tone = 'primary', ...props }) {
  return (
    <button className={`action-button action-button--${tone}`} {...props}>
      {children}
    </button>
  );
}

function Panel({ eyebrow, title, children, actions }) {
  return (
    <section className="panel-card">
      <header className="panel-card__header">
        <div>
          {eyebrow ? <p className="panel-card__eyebrow">{eyebrow}</p> : null}
          <h3>{title}</h3>
        </div>
        {actions ? <div className="panel-card__actions">{actions}</div> : null}
      </header>
      <div className="panel-card__body">{children}</div>
    </section>
  );
}

function CodeBlock({ children }) {
  return <pre className="code-block">{children}</pre>;
}

export function App() {
  const [token, setToken] = useState(getStoredToken());
  const [activePage, setActivePage] = useState('resources');
  const [message, setMessage] = useState('Ready.');
  const [response, setResponse] = useState('No response yet.');
  const [currentUser, setCurrentUser] = useState('No user loaded.');
  const [systemSummary, setSystemSummary] = useState('Dashboard summary not loaded yet.');
  const [usersPayload, setUsersPayload] = useState('Load users to view masked email, roles, and recent IP information.');
  const [latestCode, setLatestCode] = useState('No code issued yet.');
  const [metrics, setMetrics] = useState({ users: 0, securityEvents: 0, auditLogs: 0, highRisk: 0 });
  const [loginForm, setLoginForm] = useState({ email: bootstrap.demoAdminEmail || '', password: bootstrap.demoAdminPassword || '' });
  const [verifyForm, setVerifyForm] = useState({ challenge_id: '', code: '' });
  const [roleForm, setRoleForm] = useState({ email: '', role: 'admin' });
  const [deleteUserId, setDeleteUserId] = useState('');

  const isDashboardRoute = bootstrap.pageMode === 'dashboard';
  const isLoggedIn = Boolean(token);

  const currentUserEmail = useMemo(() => {
    if (!currentUser || typeof currentUser === 'string') return bootstrap.demoAdminEmail || 'operator@example.com';
    return currentUser.email || bootstrap.demoAdminEmail || 'operator@example.com';
  }, [currentUser]);

  useEffect(() => {
    if (isDashboardRoute && !token) {
      window.location.replace('/');
      return;
    }
    if (!isDashboardRoute && token) {
      window.location.replace('/dashboard');
      return;
    }
    if (isDashboardRoute && token) {
      bootstrapDashboard(token);
    }
  }, []);

  async function bootstrapDashboard(nextToken = token) {
    try {
      const [meData, dashboardData, usersData] = await Promise.all([
        apiRequest('/api/auth/me', { token: nextToken }),
        apiRequest('/api/admin/dashboard', { token: nextToken }),
        apiRequest('/api/admin/users', { token: nextToken }),
      ]);
      setCurrentUser(meData);
      setSystemSummary(dashboardData);
      setUsersPayload(usersData);
      setMetrics({
        users: usersData.users?.length || 0,
        securityEvents: dashboardData.system_summary?.security_event_count || 0,
        auditLogs: dashboardData.system_summary?.audit_log_count || 0,
        highRisk: (dashboardData.risk_summary?.users || []).filter((user) => user.risk_level === 'high').length,
      });
      setMessage(`Dashboard ready for ${meData.email}.`);
      setResponse(JSON.stringify(dashboardData, null, 2));
    } catch (error) {
      if (error.status === 401) {
        handleSignOut(false);
        return;
      }
      setMessage(`Dashboard load failed (${error.status || 'error'}).`);
      setResponse(JSON.stringify(error.data || error, null, 2));
    }
  }


  async function requestLoginCode(payload = loginForm) {
    try {
      const data = await apiRequest('/api/auth/login', { method: 'POST', body: payload });
      setVerifyForm({ challenge_id: data.challenge_id || '', code: data.demo_code || '' });
      setLatestCode(data.demo_code || 'No code issued yet.');
      setMessage('Verification code issued. Complete sign-in to open the console.');
      setResponse(JSON.stringify(data, null, 2));
    } catch (error) {
      setMessage(`Login failed (${error.status || 'error'}).`);
      setResponse(JSON.stringify(error.data || error, null, 2));
    }
  }

  async function handleVerifyCode(event) {
    event.preventDefault();
    try {
      const data = await apiRequest('/api/auth/verify-code', { method: 'POST', body: verifyForm });
      saveToken(data.access_token);
      setToken(data.access_token);
      setLatestCode(verifyForm.code || latestCode);
      window.location.assign('/dashboard');
    } catch (error) {
      setMessage(`Verification failed (${error.status || 'error'}).`);
      setResponse(JSON.stringify(error.data || error, null, 2));
    }
  }

  async function handleAction(action) {
    try {
      let data;
      if (action === 'me') {
        data = await apiRequest('/api/auth/me', { token });
        setCurrentUser(data);
      } else if (action === 'dashboard') {
        data = await apiRequest('/api/admin/dashboard', { token });
        setSystemSummary(data);
        const usersData = await apiRequest('/api/admin/users', { token });
        setUsersPayload(usersData);
      } else if (action === 'users') {
        data = await apiRequest('/api/admin/users', { token });
        setUsersPayload(data);
      } else if (action === 'security-events') {
        data = await apiRequest('/api/admin/security-events', { token });
      } else if (action === 'audit-logs') {
        data = await apiRequest('/api/admin/audit-logs', { token });
      } else if (action === 'risk-summary') {
        data = await apiRequest('/api/admin/risk-summary', { token });
      }
      if (data) {
        setResponse(JSON.stringify(data, null, 2));
        setMessage(`Loaded ${action}.`);
      }
      if (action === 'dashboard' || action === 'users' || action === 'me') {
        await bootstrapDashboard(token);
      }
    } catch (error) {
      setMessage(`Request failed for ${action} (${error.status || 'error'}).`);
      setResponse(JSON.stringify(error.data || error, null, 2));
    }
  }

  async function handleAssignRole(event) {
    event.preventDefault();
    try {
      const data = await apiRequest('/api/rbac/assign-role', { method: 'POST', body: roleForm, token });
      setMessage('Role assignment succeeded.');
      setResponse(JSON.stringify(data, null, 2));
      await bootstrapDashboard(token);
    } catch (error) {
      setMessage(`Role assignment failed (${error.status || 'error'}).`);
      setResponse(JSON.stringify(error.data || error, null, 2));
    }
  }

  async function handleDeleteUser(event) {
    event.preventDefault();
    if (!deleteUserId) return;
    try {
      const data = await apiRequest(`/api/admin/users/${deleteUserId}`, { method: 'DELETE', token });
      setMessage('User deletion succeeded.');
      setResponse(JSON.stringify(data, null, 2));
      setDeleteUserId('');
      await bootstrapDashboard(token);
    } catch (error) {
      setMessage(`User deletion failed (${error.status || 'error'}).`);
      setResponse(JSON.stringify(error.data || error, null, 2));
    }
  }

  async function handleSignOut(callApi = true) {
    if (callApi && token) {
      try {
        await apiRequest('/api/auth/logout', { method: 'POST', token });
      } catch {
        // Ignore logout cleanup failures.
      }
    }
    saveToken('');
    setToken('');
    setCurrentUser('No user loaded.');
    setSystemSummary('Dashboard summary not loaded yet.');
    setUsersPayload('Load users to view masked email, roles, and recent IP information.');
    setMetrics({ users: 0, securityEvents: 0, auditLogs: 0, highRisk: 0 });
    setLatestCode('No code issued yet.');
    setVerifyForm({ challenge_id: '', code: '' });
    setMessage('Signed out.');
    setResponse('No response yet.');
    window.location.assign('/');
  }

  function fillSeededAccess() {
    setLoginForm({ email: bootstrap.demoAdminEmail || '', password: bootstrap.demoAdminPassword || '' });
    setMessage('Seeded access credentials copied into the sign-in form.');
  }

  const renderResources = () => (
    <div className="page-grid">
      <section className="hero-strip">
        <div>
          <p className="eyebrow">Application security platform</p>
          <h1>SecureAccessAI Console</h1>
          <p className="hero-copy">
            Authentication, RBAC, audit evidence, risk scoring, and an extension lane for future network security controls.
          </p>
        </div>
        <div className="hero-strip__actions">
          <ActionButton tone="secondary" onClick={() => handleAction('me')}>Refresh Access</ActionButton>
          <ActionButton onClick={() => handleAction('dashboard')}>Refresh Dashboard</ActionButton>
        </div>
      </section>

      <section className="metrics-grid">
        <MetricCard label="Users" value={metrics.users} hint="Registered identities" />
        <MetricCard label="Security Events" value={metrics.securityEvents} hint="Threat feed items" />
        <MetricCard label="Audit Logs" value={metrics.auditLogs} hint="Tracked admin actions" />
        <MetricCard label="High Risk" value={metrics.highRisk} hint="Need review" tone="alert" />
      </section>

      <section className="two-column-grid">
        <Panel
          eyebrow="Operations"
          title="Security actions"
          actions={
            <div className="inline-actions">
              <ActionButton onClick={() => handleAction('security-events')}>Security Events</ActionButton>
              <ActionButton tone="secondary" onClick={() => handleAction('risk-summary')}>Risk Summary</ActionButton>
            </div>
          }
        >
          <div className="button-stack">
            <ActionButton tone="secondary" onClick={() => handleAction('users')}>Load Users</ActionButton>
            <ActionButton tone="secondary" onClick={() => handleAction('audit-logs')}>Audit Logs</ActionButton>
            <ActionButton tone="secondary" onClick={() => setActivePage('settings')}>Open Governance</ActionButton>
            <ActionButton tone="ghost" onClick={() => handleSignOut(true)}>Sign Out</ActionButton>
          </div>
        </Panel>

        <Panel eyebrow="Current session" title={currentUserEmail}>
          <div className="session-stack">
            <div>
              <span className="mini-label">Session token</span>
              <CodeBlock>{maskToken(token)}</CodeBlock>
            </div>
            <div>
              <span className="mini-label">Current user</span>
              <CodeBlock>{typeof currentUser === 'string' ? currentUser : JSON.stringify(currentUser, null, 2)}</CodeBlock>
            </div>
          </div>
        </Panel>
      </section>

      <section className="single-panel-grid">
        <Panel eyebrow="Network extension" title="Reserved lane for network security">
          <div className="extension-grid">
            <div><strong>Traffic anomalies</strong><span>Ingress and egress monitoring.</span></div>
            <div><strong>Asset inventory</strong><span>Hosts, ports, and exposure visibility.</span></div>
            <div><strong>Vulnerability feed</strong><span>CVE ingestion and remediation queue.</span></div>
            <div><strong>Incident response</strong><span>Escalation and containment hooks.</span></div>
          </div>
        </Panel>
      </section>
    </div>
  );

  const renderActivity = () => (
    <div className="page-grid">
      <section className="two-column-grid">
        <Panel eyebrow="Operator" title="Message log">
          <CodeBlock>{message}</CodeBlock>
        </Panel>
        <Panel eyebrow="API trace" title="Latest response">
          <CodeBlock>{response}</CodeBlock>
        </Panel>
      </section>
      <section className="two-column-grid">
        <Panel eyebrow="System summary" title="Dashboard state">
          <CodeBlock>{typeof systemSummary === 'string' ? systemSummary : JSON.stringify(systemSummary, null, 2)}</CodeBlock>
        </Panel>
        <Panel eyebrow="Inventory" title="User list">
          <CodeBlock>{typeof usersPayload === 'string' ? usersPayload : JSON.stringify(usersPayload, null, 2)}</CodeBlock>
        </Panel>
      </section>
    </div>
  );

  const renderSettings = () => (
    <div className="page-grid">
      <section className="two-column-grid">
        <Panel eyebrow="Identity" title="Assign role">
          <form className="form-grid" onSubmit={handleAssignRole}>
            <label>
              User email
              <input value={roleForm.email} onChange={(event) => setRoleForm((prev) => ({ ...prev, email: event.target.value }))} placeholder="peer@example.com" />
            </label>
            <label>
              Role
              <input value={roleForm.role} onChange={(event) => setRoleForm((prev) => ({ ...prev, role: event.target.value }))} placeholder="admin" />
            </label>
            <ActionButton type="submit">Assign Role</ActionButton>
          </form>
        </Panel>

        <Panel eyebrow="Governance" title="Delete temporary user">
          <form className="form-grid" onSubmit={handleDeleteUser}>
            <label>
              User ID
              <input value={deleteUserId} onChange={(event) => setDeleteUserId(event.target.value)} placeholder="Load users first" />
            </label>
            <div className="inline-actions">
              <ActionButton tone="secondary" type="button" onClick={() => handleAction('users')}>Load Users</ActionButton>
              <ActionButton type="submit">Delete User</ActionButton>
            </div>
          </form>
        </Panel>
      </section>

      <section className="single-panel-grid">
        <Panel eyebrow="Data governance" title="Protection defaults">
          <ul className="policy-list">
            <li>Admin feeds mask personal identifiers by default.</li>
            <li>Time-limited verification codes are required before token issue.</li>
            <li>Audit trails preserve IP context while reducing unnecessary exposure.</li>
            <li>Future network evidence will follow the same privacy-aware handling model.</li>
          </ul>
        </Panel>
      </section>
    </div>
  );

  if (!isDashboardRoute) {
    return (
      <div className="login-shell">
        <aside className="login-side">
          <div className="brand-pill">SA</div>
          <p className="eyebrow">SecureAccessAI</p>
          <h1>Application security console</h1>
          <p className="hero-copy">
            Sign in with password and a time-limited code, then enter the operations console for audit, threat monitoring, and governance controls.
          </p>
          <div className="login-side__cards">
            <div>
              <strong>Authentication</strong>
              <span>Password + verification code.</span>
            </div>
            <div>
              <strong>Control plane</strong>
              <span>RBAC, audit logs, risk summary.</span>
            </div>
            <div>
              <strong>Extension ready</strong>
              <span>Prepared for network security modules.</span>
            </div>
          </div>
        </aside>

        <main className="login-main">
          <section className="login-grid login-grid--compact">
            <Panel eyebrow="Sign in" title="Request verification code">
              <form className="form-grid" onSubmit={(event) => { event.preventDefault(); requestLoginCode(); }}>
                <label>
                  Email
                  <input value={loginForm.email} onChange={(event) => setLoginForm((prev) => ({ ...prev, email: event.target.value }))} placeholder="lead@example.com" />
                </label>
                <label>
                  Password
                  <input type="password" value={loginForm.password} onChange={(event) => setLoginForm((prev) => ({ ...prev, password: event.target.value }))} placeholder="Pass1234!" />
                </label>
                <ActionButton type="submit" disabled={!loginForm.email || !loginForm.password}>Request Code</ActionButton>
              </form>
            </Panel>

            <Panel eyebrow="Verify" title="Complete sign-in">
              <form className="form-grid" onSubmit={handleVerifyCode}>
                <label>
                  Challenge ID
                  <input value={verifyForm.challenge_id} onChange={(event) => setVerifyForm((prev) => ({ ...prev, challenge_id: event.target.value }))} placeholder="Auto-filled after login" />
                </label>
                <label>
                  Code
                  <input value={verifyForm.code} onChange={(event) => setVerifyForm((prev) => ({ ...prev, code: event.target.value }))} placeholder="6-digit code" />
                </label>
                <ActionButton type="submit" disabled={!verifyForm.challenge_id || !verifyForm.code}>Verify and Open Console</ActionButton>
              </form>
              <div className="code-strip">
                <span className="mini-label">Latest verification code</span>
                <CodeBlock>{latestCode}</CodeBlock>
              </div>
            </Panel>

            <Panel eyebrow="Seeded access" title="Quick operator login">
              <div className="seeded-card">
                <p><span>Username</span><code>{bootstrap.demoAdminUsername || 'demo-admin'}</code></p>
                <p><span>Email</span><code>{bootstrap.demoAdminEmail || 'Not configured'}</code></p>
                <p><span>Password</span><code>{bootstrap.demoAdminPassword || 'Not configured'}</code></p>
              </div>
              <div className="inline-actions">
                <ActionButton tone="secondary" onClick={fillSeededAccess}>Use Seeded Access</ActionButton>
                <ActionButton onClick={() => requestLoginCode({ email: bootstrap.demoAdminEmail, password: bootstrap.demoAdminPassword })} disabled={!bootstrap.demoAdminEmail || !bootstrap.demoAdminPassword}>Request Code</ActionButton>
              </div>
            </Panel>
          </section>

          <section className="status-row status-row--single">
            <Panel eyebrow="Status" title="Authentication status">
              <CodeBlock>{message}</CodeBlock>
            </Panel>
          </section>
        </main>
      </div>
    );
  }

  return (
    <div className="console-shell">
      <aside className="console-sidebar">
        <div className="console-sidebar__brand">
          <div className="brand-pill brand-pill--small">SA</div>
          <div>
            <p className="eyebrow">Platform</p>
            <h2>SecureAccessAI</h2>
          </div>
        </div>
        <nav className="console-nav">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              className={item.id === activePage ? 'console-nav__item is-active' : 'console-nav__item'}
              onClick={() => setActivePage(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <div className="console-sidebar__subnav">
          <p className="menu-heading">Manage</p>
          {RESOURCE_ITEMS.map((item) => (
            <button
              key={item.id}
              className={activePage === 'resources' ? 'console-subnav__item is-active' : 'console-subnav__item'}
              onClick={() => setActivePage(item.id === 'network' ? 'resources' : 'resources')}
            >
              {item.label}
            </button>
          ))}
        </div>
      </aside>

      <main className="console-main">
        <header className="console-topbar">
          <div className="console-search">Search users, IPs, actions, and risk signals</div>
          <div className="console-topbar__actions">
            <ActionButton>Create</ActionButton>
            <div className="tenant-chip">Kale Health Tenant</div>
            <div className="operator-chip">{currentUserEmail}</div>
          </div>
        </header>

        <section className="console-tabs">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              className={item.id === activePage ? 'console-tabs__item is-active' : 'console-tabs__item'}
              onClick={() => setActivePage(item.id)}
            >
              {item.label}
            </button>
          ))}
        </section>

        {activePage === 'resources' ? renderResources() : null}
        {activePage === 'activity' ? renderActivity() : null}
        {activePage === 'settings' ? renderSettings() : null}
      </main>
    </div>
  );
}
