import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Avatar,
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  Input,
  Layout,
  List,
  Menu,
  Progress,
  Row,
  Space,
  Statistic,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd';
import {
  AuditOutlined,
  CloudServerOutlined,
  DatabaseOutlined,
  DeleteOutlined,
  KeyOutlined,
  LockOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  SecurityScanOutlined,
  SettingOutlined,
  TeamOutlined,
  UserOutlined,
} from '@ant-design/icons';

const { Header, Sider, Content } = Layout;
const { Title, Text, Paragraph } = Typography;

const bootstrap = window.SECUREACCESS_BOOTSTRAP || {};
const TOKEN_KEY = 'secureaccessai_console_token';
const LEGACY_TOKEN_KEY = 'secureaccessai_demo_token';
const DEFAULT_USERS_MESSAGE = 'Load users to view masked email, roles, and recent IP information.';
const DEFAULT_SYSTEM_MESSAGE = 'Dashboard summary not loaded yet.';
const DEFAULT_RESPONSE_MESSAGE = 'No response yet.';

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

function prettyJson(value) {
  if (typeof value === 'string') return value;
  return JSON.stringify(value, null, 2);
}

function maskToken(token) {
  if (!token) return 'No token';
  return `${token.slice(0, 24)}...${token.slice(-8)}`;
}

function riskStatusTone(highRisk) {
  if (highRisk > 0) return 'exception';
  return 'success';
}

function responseTag(statusText) {
  if (/failed|error/i.test(statusText)) return 'error';
  if (/ready|loaded|succeeded|success/i.test(statusText)) return 'success';
  return 'info';
}

function parseUsers(usersPayload) {
  if (!usersPayload || typeof usersPayload === 'string') return [];
  return (usersPayload.users || []).map((user) => ({
    key: user.id,
    id: user.id,
    username: user.username,
    email: user.masked_email,
    roles: user.roles || [],
    lastIp: user.last_ip_address || 'No activity yet',
    active: user.is_active,
  }));
}

function parseAuditRows(response) {
  if (!response || typeof response === 'string') return [];
  const logs = response.logs || [];
  return logs.map((log) => ({
    key: log.id,
    action: log.action,
    target: log.target_email || 'System',
    status: log.status,
    detail: log.detail || '-',
    createdAt: log.created_at,
  }));
}

function parseEventRows(response) {
  if (!response || typeof response === 'string') return [];
  const events = response.events || [];
  return events.map((event) => ({
    key: event.id,
    email: event.email,
    ip: event.ip_address,
    type: event.event_type,
    outcome: event.outcome,
    risk: event.risk_score,
    createdAt: event.created_at,
  }));
}

function parseRiskRows(response) {
  if (!response || typeof response === 'string') return [];
  const users = response.risk_summary?.users || response.users || [];
  return users.map((user, index) => ({
    key: `${user.email}-${index}`,
    email: user.email,
    level: user.risk_level,
    score: user.risk_score,
    failedAttempts: user.failed_attempts,
    blockedAttempts: user.blocked_attempts,
    recentIps: user.recent_ip_count,
  }));
}

function LoginPage({
  loginForm,
  setLoginForm,
  verifyForm,
  setVerifyForm,
  latestCode,
  message,
  response,
  requestLoginCode,
  handleVerifyCode,
}) {
  return (
    <div className="console-login-page">
      <div className="console-login-shell">
        <div className="console-login-hero">
          <div className="console-login-brand">
            <Avatar shape="square" size={56} style={{ background: '#173da6', fontWeight: 700 }}>SA</Avatar>
            <div>
              <Text className="section-label">Security Workspace</Text>
              <Title level={2} style={{ margin: 0 }}>SecureAccessAI Control Plane</Title>
            </div>
          </div>
          <Paragraph className="console-muted" style={{ fontSize: 16, maxWidth: 620 }}>
            Enterprise-style access workflow with password verification, authenticator QR setup, RBAC, audit trails, and threat monitoring.
          </Paragraph>
          <Row gutter={[16, 16]}>
            <Col xs={24} md={8}>
              <Card>
                <Statistic title="Auth Mode" value="Password + TOTP" />
              </Card>
            </Col>
            <Col xs={24} md={8}>
              <Card>
                <Statistic title="Risk Engine" value="IP + Anomaly" />
              </Card>
            </Col>
            <Col xs={24} md={8}>
              <Card>
                <Statistic title="Ops Surface" value="Audit + RBAC" />
              </Card>
            </Col>
          </Row>
        </div>

        <Row justify="center" gutter={[20, 20]}>
          <Col xs={24} lg={16} xl={14}>
            <Card title="Sign in" extra={<Tag color="blue">Password + Authenticator</Tag>}>
              <Form layout="vertical" onFinish={() => requestLoginCode()}>
                <Row gutter={[16, 0]}>
                  <Col xs={24}>
                    <Form.Item label="Email">
                      <Input
                        size="large"
                        prefix={<UserOutlined />}
                        value={loginForm.email}
                        onChange={(event) => setLoginForm((prev) => ({ ...prev, email: event.target.value }))}
                        placeholder="demo-admin@example.com"
                      />
                    </Form.Item>
                  </Col>
                  <Col xs={24}>
                    <Form.Item label="Password">
                      <Input.Password
                        size="large"
                        prefix={<LockOutlined />}
                        value={loginForm.password}
                        onChange={(event) => setLoginForm((prev) => ({ ...prev, password: event.target.value }))}
                        placeholder="Pass1234!"
                      />
                    </Form.Item>
                  </Col>
                  <Col xs={24} md={14}>
                    <Button type="primary" size="large" htmlType="submit" disabled={!loginForm.email || !loginForm.password} block>
                      Request Verification Code
                    </Button>
                  </Col>
                  <Col xs={24} md={10}>
                    <Tag color="processing" className="login-inline-tag">Fallback code: {latestCode}</Tag>
                  </Col>
                </Row>
              </Form>

              <div className="login-divider" />

              <Form layout="vertical" onFinish={handleVerifyCode}>
                <Row gutter={[16, 0]}>
                  <Col xs={24}>
                    <Form.Item label="Challenge ID">
                      <Input
                        size="large"
                        prefix={<KeyOutlined />}
                        value={verifyForm.challenge_id}
                        onChange={(event) => setVerifyForm((prev) => ({ ...prev, challenge_id: event.target.value }))}
                        placeholder="Auto-filled after requesting the code"
                      />
                    </Form.Item>
                  </Col>
                  <Col xs={24}>
                    <Form.Item label="Authenticator code">
                      <Input
                        size="large"
                        prefix={<SafetyCertificateOutlined />}
                        value={verifyForm.code}
                        onChange={(event) => setVerifyForm((prev) => ({ ...prev, code: event.target.value }))}
                        placeholder="Enter the current 6-digit code"
                      />
                    </Form.Item>
                  </Col>
                  <Col xs={24}>
                    <Button type="primary" size="large" htmlType="submit" disabled={!verifyForm.challenge_id || !verifyForm.code} block>
                      Verify and Open Console
                    </Button>
                  </Col>
                </Row>
              </Form>
            </Card>
          </Col>

          <Col xs={24} lg={8} xl={6}>
            <Card title="Status">
              <Space direction="vertical" size={16} style={{ width: '100%' }}>
                <Alert type={responseTag(message)} showIcon message={message} />
                <Text type="secondary">
                  Authenticator already enrolled. Request the challenge, then enter the current 6-digit code from Microsoft Authenticator.
                </Text>
                <Text type="secondary">
                  Latest API response
                </Text>
                <pre className="json-block">{response}</pre>
              </Space>
            </Card>
          </Col>
        </Row>
      </div>
    </div>
  );
}

function AppDashboard({
  activePage,
  setActivePage,
  message,
  response,
  currentUser,
  currentUserEmail,
  systemSummary,
  usersPayload,
  metrics,
  token,
  handleAction,
  handleAssignRole,
  handleDeleteUser,
  handleSignOut,
  roleForm,
  setRoleForm,
  deleteUserId,
  setDeleteUserId,
}) {
  const auditRows = parseAuditRows(response);
  const eventRows = parseEventRows(response);
  const riskRows = parseRiskRows(response);
  const usersRows = parseUsers(usersPayload);

  const menuItems = [
    { key: 'resources', icon: <CloudServerOutlined />, label: 'Resources' },
    { key: 'activity', icon: <AuditOutlined />, label: 'Activity' },
    { key: 'settings', icon: <SettingOutlined />, label: 'Settings' },
  ];

  const topTabs = [
    { key: 'resources', label: 'Resources' },
    { key: 'activity', label: 'Activity' },
    { key: 'settings', label: 'Settings' },
  ];

  const summary = typeof systemSummary === 'string' ? null : systemSummary;
  const users = summary?.risk_summary?.users || [];
  const avgRisk = users.length
    ? Math.round(users.reduce((acc, item) => acc + (item.risk_score || 0), 0) / users.length)
    : 0;

  const userColumns = [
    { title: 'User', dataIndex: 'username', key: 'username' },
    { title: 'Masked Email', dataIndex: 'email', key: 'email' },
    { title: 'Roles', dataIndex: 'roles', key: 'roles', render: (roles) => <Space wrap>{roles.map((role) => <Tag key={role}>{role}</Tag>)}</Space> },
    { title: 'Last IP', dataIndex: 'lastIp', key: 'lastIp' },
    { title: 'Status', dataIndex: 'active', key: 'active', render: (active) => <Tag color={active ? 'green' : 'red'}>{active ? 'Active' : 'Disabled'}</Tag> },
  ];

  const activityColumns = [
    { title: 'Action', dataIndex: 'action', key: 'action' },
    { title: 'Target', dataIndex: 'target', key: 'target' },
    { title: 'Status', dataIndex: 'status', key: 'status', render: (status) => <Tag color={status === 'success' ? 'green' : status === 'failed' ? 'red' : 'blue'}>{status}</Tag> },
    { title: 'Detail', dataIndex: 'detail', key: 'detail', ellipsis: true },
  ];

  const eventColumns = [
    { title: 'Email', dataIndex: 'email', key: 'email' },
    { title: 'IP', dataIndex: 'ip', key: 'ip' },
    { title: 'Type', dataIndex: 'type', key: 'type' },
    { title: 'Outcome', dataIndex: 'outcome', key: 'outcome', render: (outcome) => <Tag color={outcome === 'success' ? 'green' : outcome === 'blocked' ? 'red' : 'gold'}>{outcome}</Tag> },
    { title: 'Risk', dataIndex: 'risk', key: 'risk' },
  ];

  const riskColumns = [
    { title: 'Email', dataIndex: 'email', key: 'email' },
    { title: 'Level', dataIndex: 'level', key: 'level', render: (level) => <Tag color={level === 'high' ? 'red' : level === 'medium' ? 'gold' : 'green'}>{level}</Tag> },
    { title: 'Risk Score', dataIndex: 'score', key: 'score' },
    { title: 'Failed', dataIndex: 'failedAttempts', key: 'failedAttempts' },
    { title: 'Blocked', dataIndex: 'blockedAttempts', key: 'blockedAttempts' },
    { title: 'Recent IPs', dataIndex: 'recentIps', key: 'recentIps' },
  ];

  return (
    <Layout className="antd-console-layout">
      <Sider width={248} theme="dark" className="antd-console-sider">
        <div className="console-sider-brand">
          <Avatar shape="square" size={42} style={{ background: '#173da6', fontWeight: 700 }}>SA</Avatar>
          <div>
            <div className="section-label section-label--dark">Platform</div>
            <div className="console-sider-title">SecureAccessAI</div>
          </div>
        </div>
        <Menu theme="dark" mode="inline" selectedKeys={[activePage]} items={menuItems} onClick={({ key }) => setActivePage(key)} />
        <div className="console-sider-footer">
          <Text className="console-sider-copy">Application security workspace with room for future network security controls.</Text>
        </div>
      </Sider>
      <Layout>
        <Header className="antd-console-header">
          <div className="header-search-shell">
            <SearchOutlined />
            <span>Search users, IPs, audit actions, and risk signals</span>
          </div>
          <Space size={12}>
            <Button type="primary">Create</Button>
            <Tag color="blue">Ready for demo</Tag>
            <Avatar icon={<UserOutlined />} />
          </Space>
        </Header>
        <Content className="antd-console-content">
          <div className="console-page-head">
            <div>
              <Text className="section-label">Application security platform</Text>
              <Title level={2} style={{ marginTop: 4, marginBottom: 8 }}>SecureAccessAI Dashboard</Title>
              <Text type="secondary">Signed in as {currentUserEmail}. Password plus authenticator login is active for this workspace.</Text>
            </div>
            <Space wrap>
              <Button icon={<DatabaseOutlined />} onClick={() => handleAction('me')}>Refresh Access</Button>
              <Button type="primary" icon={<RadarChartOutlined />} onClick={() => handleAction('dashboard')}>Refresh Dashboard</Button>
              <Button danger onClick={() => handleSignOut(true)}>Sign Out</Button>
            </Space>
          </div>

          <Tabs activeKey={activePage} items={topTabs} onChange={setActivePage} />

          {activePage === 'resources' && (
            <Space direction="vertical" size={16} style={{ width: '100%' }}>
              <Row gutter={[16, 16]}>
                <Col xs={24} md={12} xl={6}><Card><Statistic title="Users" value={metrics.users} prefix={<TeamOutlined />} /></Card></Col>
                <Col xs={24} md={12} xl={6}><Card><Statistic title="Security Events" value={metrics.securityEvents} prefix={<SecurityScanOutlined />} /></Card></Col>
                <Col xs={24} md={12} xl={6}><Card><Statistic title="Audit Logs" value={metrics.auditLogs} prefix={<AuditOutlined />} /></Card></Col>
                <Col xs={24} md={12} xl={6}><Card><Statistic title="High Risk" value={metrics.highRisk} valueStyle={{ color: metrics.highRisk ? '#dc2626' : '#16a34a' }} prefix={<SafetyCertificateOutlined />} /></Card></Col>
              </Row>

              <Row gutter={[16, 16]}>
                <Col xs={24} xl={8}>
                  <Card title="Risk Posture" extra={<Tag color={metrics.highRisk ? 'red' : 'green'}>{metrics.highRisk ? 'Attention needed' : 'Stable'}</Tag>}>
                    <div className="chart-center-wrap">
                      <Progress type="dashboard" percent={Math.min(avgRisk, 100)} status={riskStatusTone(metrics.highRisk)} />
                      <div className="chart-copy">
                        <div className="chart-big">{avgRisk}</div>
                        <div className="chart-small">Average risk score</div>
                      </div>
                    </div>
                  </Card>
                </Col>
                <Col xs={24} xl={16}>
                  <Card title="Risk Summary" extra={<Button size="small" onClick={() => handleAction('risk-summary')}>Load latest</Button>}>
                    <Table columns={riskColumns} dataSource={riskRows} pagination={false} size="small" scroll={{ x: 720 }} locale={{ emptyText: 'Load Risk Summary to populate this table.' }} />
                  </Card>
                </Col>
              </Row>

              <Card title="Identity Inventory" extra={<Button size="small" onClick={() => handleAction('users')}>Load users</Button>}>
                <Table columns={userColumns} dataSource={usersRows} pagination={{ pageSize: 6 }} size="middle" scroll={{ x: 860 }} />
              </Card>
            </Space>
          )}

          {activePage === 'activity' && (
            <Space direction="vertical" size={16} style={{ width: '100%' }}>
              <Alert type={responseTag(message)} showIcon message={message} />
              <Row gutter={[16, 16]}>
                <Col xs={24} xl={12}>
                  <Card title="Security Event Feed" extra={<Button size="small" onClick={() => handleAction('security-events')}>Refresh</Button>}>
                    <Table columns={eventColumns} dataSource={eventRows} pagination={{ pageSize: 5 }} size="small" scroll={{ x: 760 }} locale={{ emptyText: 'Load Security Events to populate this table.' }} />
                  </Card>
                </Col>
                <Col xs={24} xl={12}>
                  <Card title="Audit Trail" extra={<Button size="small" onClick={() => handleAction('audit-logs')}>Refresh</Button>}>
                    <Table columns={activityColumns} dataSource={auditRows} pagination={{ pageSize: 5 }} size="small" scroll={{ x: 760 }} locale={{ emptyText: 'Load Audit Logs to populate this table.' }} />
                  </Card>
                </Col>
              </Row>
              <Row gutter={[16, 16]}>
                <Col xs={24} xl={12}>
                  <Card title="Latest API response"><pre className="json-block">{response}</pre></Card>
                </Col>
                <Col xs={24} xl={12}>
                  <Card title="Current user and session">
                    <Descriptions size="small" column={1} bordered>
                      <Descriptions.Item label="Operator">{currentUserEmail}</Descriptions.Item>
                      <Descriptions.Item label="Session token"><span className="mono-inline">{maskToken(token)}</span></Descriptions.Item>
                      <Descriptions.Item label="Current user payload"><pre className="json-block json-block--compact">{prettyJson(currentUser)}</pre></Descriptions.Item>
                    </Descriptions>
                  </Card>
                </Col>
              </Row>
            </Space>
          )}

          {activePage === 'settings' && (
            <Row gutter={[16, 16]}>
              <Col xs={24} xl={10}>
                <Card title="Assign role" extra={<Tag color="blue">RBAC</Tag>}>
                  <Form layout="vertical" onFinish={handleAssignRole}>
                    <Form.Item label="User email">
                      <Input value={roleForm.email} onChange={(event) => setRoleForm((prev) => ({ ...prev, email: event.target.value }))} prefix={<UserOutlined />} placeholder="peer@example.com" />
                    </Form.Item>
                    <Form.Item label="Role">
                      <Input value={roleForm.role} onChange={(event) => setRoleForm((prev) => ({ ...prev, role: event.target.value }))} prefix={<KeyOutlined />} placeholder="admin" />
                    </Form.Item>
                    <Button type="primary" htmlType="submit">Assign Role</Button>
                  </Form>
                </Card>
              </Col>
              <Col xs={24} xl={10}>
                <Card title="Delete temporary user" extra={<Tag color="red">Governance</Tag>}>
                  <Form layout="vertical" onFinish={handleDeleteUser}>
                    <Form.Item label="User ID">
                      <Input value={deleteUserId} onChange={(event) => setDeleteUserId(event.target.value)} prefix={<DeleteOutlined />} placeholder="Load users first" />
                    </Form.Item>
                    <Space>
                      <Button onClick={() => handleAction('users')}>Load Users</Button>
                      <Button danger type="primary" htmlType="submit">Delete User</Button>
                    </Space>
                  </Form>
                </Card>
              </Col>
              <Col xs={24} xl={4}>
                <Card title="Governance defaults">
                  <List
                    size="small"
                    dataSource={[
                      'PII masking enabled by default',
                      'Password + second factor required',
                      'Audit trail retains masked IP context',
                      'Network security module reserved for future expansion',
                    ]}
                    renderItem={(item) => <List.Item>{item}</List.Item>}
                  />
                </Card>
              </Col>
            </Row>
          )}
        </Content>
      </Layout>
    </Layout>
  );
}

export function App() {
  const [token, setToken] = useState(getStoredToken());
  const [activePage, setActivePage] = useState('resources');
  const [message, setMessage] = useState('Ready.');
  const [response, setResponse] = useState(DEFAULT_RESPONSE_MESSAGE);
  const [currentUser, setCurrentUser] = useState('No user loaded.');
  const [systemSummary, setSystemSummary] = useState(DEFAULT_SYSTEM_MESSAGE);
  const [usersPayload, setUsersPayload] = useState(DEFAULT_USERS_MESSAGE);
  const [latestCode, setLatestCode] = useState('No code issued yet.');
  const [metrics, setMetrics] = useState({ users: 0, securityEvents: 0, auditLogs: 0, highRisk: 0 });
  const [loginForm, setLoginForm] = useState({ email: bootstrap.demoAdminEmail || '', password: bootstrap.demoAdminPassword || '' });
  const [verifyForm, setVerifyForm] = useState({ challenge_id: '', code: '' });
  const [roleForm, setRoleForm] = useState({ email: '', role: 'admin' });
  const [deleteUserId, setDeleteUserId] = useState('');

  const isDashboardRoute = bootstrap.pageMode === 'dashboard';

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
      setLatestCode(data.demo_code || 'Use the 6-digit code from your authenticator app.');
      setMessage(data.totp_enabled
        ? 'Password accepted. Enter the 6-digit code from your authenticator app to open the console.'
        : 'Verification code issued. Complete sign-in to open the console.');
      setResponse(JSON.stringify(data, null, 2));
    } catch (error) {
      setMessage(`Login failed (${error.status || 'error'}).`);
      setResponse(JSON.stringify(error.data || error, null, 2));
    }
  }

  async function handleVerifyCode() {
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

  async function handleAssignRole() {
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

  async function handleDeleteUser() {
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
      }
    }
    saveToken('');
    setToken('');
    setCurrentUser('No user loaded.');
    setSystemSummary(DEFAULT_SYSTEM_MESSAGE);
    setUsersPayload(DEFAULT_USERS_MESSAGE);
    setMetrics({ users: 0, securityEvents: 0, auditLogs: 0, highRisk: 0 });
    setLatestCode('No code issued yet.');
    setVerifyForm({ challenge_id: '', code: '' });
    setMessage('Signed out.');
    setResponse(DEFAULT_RESPONSE_MESSAGE);
    window.location.assign('/');
  }

  if (!isDashboardRoute) {
    return (
      <LoginPage
        loginForm={loginForm}
        setLoginForm={setLoginForm}
        verifyForm={verifyForm}
        setVerifyForm={setVerifyForm}
        latestCode={latestCode}
        message={message}
        response={response}
        requestLoginCode={requestLoginCode}
        handleVerifyCode={handleVerifyCode}
      />
    );
  }

  return (
    <AppDashboard
      activePage={activePage}
      setActivePage={setActivePage}
      message={message}
      response={response}
      currentUser={currentUser}
      currentUserEmail={currentUserEmail}
      systemSummary={systemSummary}
      usersPayload={usersPayload}
      metrics={metrics}
      token={token}
      handleAction={handleAction}
      handleAssignRole={handleAssignRole}
      handleDeleteUser={handleDeleteUser}
      handleSignOut={handleSignOut}
      roleForm={roleForm}
      setRoleForm={setRoleForm}
      deleteUserId={deleteUserId}
      setDeleteUserId={setDeleteUserId}
    />
  );
}
