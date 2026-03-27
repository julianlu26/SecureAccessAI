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
  Tag,
  Typography,
} from 'antd';
import {
  AuditOutlined,
  BellOutlined,
  BgColorsOutlined,
  CloudServerOutlined,
  DeleteOutlined,
  GlobalOutlined,
  KeyOutlined,
  LockOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  SecurityScanOutlined,
  TeamOutlined,
  UserOutlined,
} from '@ant-design/icons';

const { Header, Sider, Content } = Layout;
const { Title, Text, Paragraph } = Typography;

const bootstrap = window.SECUREACCESS_BOOTSTRAP || {};
const TOKEN_KEY = 'secureaccessai_console_token';
const LEGACY_TOKEN_KEY = 'secureaccessai_demo_token';
const DEFAULT_RESPONSE_MESSAGE = 'No response yet.';
const INITIAL_METRICS = { users: 0, adminUsers: 0, securityEvents: 0, auditLogs: 0, highRisk: 0, suspiciousNow: 0 };

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
  if (token) headers.Authorization = 'Bearer ' + token;

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
  return token.slice(0, 18) + '...' + token.slice(-8);
}

function responseTone(message) {
  if (/failed|error|forbidden/i.test(message)) return 'error';
  if (/rate limit|blocked|challenge/i.test(message)) return 'warning';
  if (/ready|loaded|success|signed/i.test(message)) return 'success';
  return 'info';
}

function parseUsers(usersPayload) {
  const users = usersPayload?.users || [];
  return users.map((user) => ({
    key: user.id,
    id: user.id,
    username: user.username,
    email: user.masked_email,
    roles: user.roles || [],
    lastIp: user.last_ip_address || 'No activity yet',
    createdAt: user.created_at,
    active: user.is_active,
  }));
}

function parseAuditRows(payload) {
  const logs = payload?.logs || payload?.recent_audit_logs || [];
  return logs.map((log) => ({
    key: log.id,
    action: log.action,
    target: log.target_email || 'System',
    status: log.status,
    detail: log.detail || '-',
    createdAt: log.created_at,
  }));
}

function parseEventRows(payload) {
  const events = payload?.events || payload?.recent_security_events || [];
  return events.map((event) => ({
    key: event.id,
    email: event.email,
    ip: event.ip_address,
    type: event.event_type,
    outcome: event.outcome,
    risk: event.risk_score,
    detail: event.detail || '-',
    createdAt: event.created_at,
  }));
}

function parseRiskRows(payload) {
  const users = payload?.risk_summary?.users || [];
  return users.map((user, index) => ({
    key: String(user.email) + '-' + String(index),
    email: user.email,
    level: user.risk_level,
    score: user.risk_score,
    failedAttempts: user.failed_attempts,
    blockedAttempts: user.blocked_attempts,
    recentIps: user.recent_ip_count,
  }));
}

function governanceItems(dataGovernance) {
  if (!dataGovernance) {
    return [
      'PII is masked by default for admin feeds.',
      'Only authorised roles can view sensitive operational data.',
      'Network security controls can be attached as future modules.',
    ];
  }
  return [
    dataGovernance.pii_policy,
    dataGovernance.data_minimisation,
    dataGovernance.network_security_extension,
  ].filter(Boolean);
}

function LoginPage({ loginForm, setLoginForm, verifyForm, setVerifyForm, message, requestLoginCode, handleVerifyCode }) {
  return (
    <div className="console-login-page">
      <div className="login-shell login-shell--narrow">
        <div className="login-simple-head">
          <div className="login-hero-badge">SecureAccessAI</div>
          <Title level={1} className="login-title">Sign in</Title>
          <Paragraph className="console-muted login-copy login-copy--compact">
            Use your email, password, and the 6-digit code from Microsoft Authenticator to open the security console.
          </Paragraph>
        </div>

        <Card className="login-main-card login-main-card--single">
          <Form layout="vertical" onFinish={() => requestLoginCode()}>
            <Form.Item label="Email">
              <Input
                size="large"
                prefix={<UserOutlined />}
                value={loginForm.email}
                onChange={(event) => setLoginForm((prev) => ({ ...prev, email: event.target.value }))}
                placeholder="demo-admin@example.com"
              />
            </Form.Item>
            <Form.Item label="Password">
              <Input.Password
                size="large"
                prefix={<LockOutlined />}
                value={loginForm.password}
                onChange={(event) => setLoginForm((prev) => ({ ...prev, password: event.target.value }))}
                placeholder="Enter account password"
              />
            </Form.Item>
            <Button type="primary" size="large" htmlType="submit" disabled={!loginForm.email || !loginForm.password} block>
              Request Verification Code
            </Button>
          </Form>

          <div className="login-divider" />

          <Form layout="vertical" onFinish={handleVerifyCode}>
            <Form.Item label="Authenticator code">
              <Input
                size="large"
                prefix={<SafetyCertificateOutlined />}
                value={verifyForm.code}
                onChange={(event) => setVerifyForm((prev) => ({ ...prev, code: event.target.value }))}
                placeholder="Enter the current 6-digit code"
              />
            </Form.Item>
            <Button type="primary" size="large" htmlType="submit" disabled={!verifyForm.challenge_id || !verifyForm.code} block>
              Verify and Open Console
            </Button>
          </Form>

          <div className="login-note-row">
            <Alert type={responseTone(message)} showIcon message={message} />
            <Text type="secondary">Challenge details are handled in the background after you request a verification code.</Text>
          </div>
        </Card>
      </div>
    </div>
  );
}

function OverviewSection({ metrics, systemSummary, riskRows, auditRows, eventRows, refreshAll }) {
  const riskAverage = riskRows.length
    ? Math.round(riskRows.reduce((acc, row) => acc + (row.score || 0), 0) / riskRows.length)
    : 0;
  const recentAudit = auditRows.slice(0, 5);
  const recentEvents = eventRows.slice(0, 5);
  const summary = systemSummary?.system_summary || {};

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div className="module-header">
        <div>
          <Text className="section-label">Administrator overview</Text>
          <Title level={3}>Security posture and current operational state</Title>
        </div>
        <Button type="primary" onClick={refreshAll}>Refresh overview</Button>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} md={12} xl={6}><Card><Statistic title="Total users" value={metrics.users} prefix={<TeamOutlined />} /></Card></Col>
        <Col xs={24} md={12} xl={6}><Card><Statistic title="Admin users" value={metrics.adminUsers} prefix={<SafetyCertificateOutlined />} /></Card></Col>
        <Col xs={24} md={12} xl={6}><Card><Statistic title="Security events" value={metrics.securityEvents} prefix={<SecurityScanOutlined />} /></Card></Col>
        <Col xs={24} md={12} xl={6}><Card><Statistic title="High risk users" value={metrics.highRisk} valueStyle={{ color: metrics.highRisk ? '#dc2626' : '#16a34a' }} prefix={<RadarChartOutlined />} /></Card></Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={8}>
          <Card title="Risk posture">
            <div className="chart-center-wrap">
              <Progress type="dashboard" percent={Math.min(riskAverage, 100)} status={metrics.highRisk ? 'exception' : 'success'} />
              <div className="chart-copy">
                <div className="chart-big">{riskAverage}</div>
                <div className="chart-small">Average risk score</div>
                <div className="chart-small">Suspicious users now: {metrics.suspiciousNow}</div>
              </div>
            </div>
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title="System summary">
            <List
              size="small"
              dataSource={[
                'Login success events: ' + String(summary.successful_logins || 0),
                'Login failures: ' + String(summary.failed_logins || 0),
                'Rate-limited events: ' + String(summary.rate_limited_events || 0),
                'Most recent suspicious activity: ' + String(summary.last_suspicious_event_at || 'Not detected yet'),
              ]}
              renderItem={(item) => <List.Item>{item}</List.Item>}
            />
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title="Platform scope">
            <List
              size="small"
              dataSource={[
                'Login and verification',
                'Identity and role governance',
                'Threat monitoring and anomaly scoring',
                'Audit and activity evidence',
                'Privacy masking and governance defaults',
              ]}
              renderItem={(item) => <List.Item>{item}</List.Item>}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <Card title="Recent security events">
            <List
              itemLayout="horizontal"
              dataSource={recentEvents}
              locale={{ emptyText: 'No security events loaded yet.' }}
              renderItem={(item) => (
                <List.Item>
                  <List.Item.Meta
                    title={String(item.type) + ' • ' + String(item.email)}
                    description={String(item.createdAt) + ' • ' + String(item.ip) + ' • risk ' + String(item.risk)}
                  />
                  <Tag color={item.outcome === 'success' ? 'green' : item.outcome === 'blocked' ? 'red' : 'gold'}>{item.outcome}</Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>
        <Col xs={24} xl={12}>
          <Card title="Recent audit activity">
            <List
              itemLayout="horizontal"
              dataSource={recentAudit}
              locale={{ emptyText: 'No audit activity loaded yet.' }}
              renderItem={(item) => (
                <List.Item>
                  <List.Item.Meta
                    title={String(item.action) + ' • ' + String(item.target)}
                    description={String(item.createdAt) + ' • ' + String(item.detail)}
                  />
                  <Tag color={item.status === 'success' ? 'green' : 'red'}>{item.status}</Tag>
                </List.Item>
              )}
            />
          </Card>
        </Col>
      </Row>
    </Space>
  );
}

function IdentitySection({ currentUser, currentUserEmail, token, usersRows, roleForm, setRoleForm, deleteUserId, setDeleteUserId, handleAssignRole, handleDeleteUser, refreshUsers }) {
  const userColumns = [
    { title: 'User', dataIndex: 'username', key: 'username' },
    { title: 'Masked Email', dataIndex: 'email', key: 'email' },
    { title: 'Roles', dataIndex: 'roles', key: 'roles', render: (roles) => <Space wrap>{roles.map((role) => <Tag key={role}>{role}</Tag>)}</Space> },
    { title: 'Last IP', dataIndex: 'lastIp', key: 'lastIp' },
    { title: 'Status', dataIndex: 'active', key: 'active', render: (active) => <Tag color={active ? 'green' : 'red'}>{active ? 'Active' : 'Disabled'}</Tag> },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div className="module-header">
        <div>
          <Text className="section-label">Identity and access</Text>
          <Title level={3}>Roles, permissions, operators, and account administration</Title>
        </div>
        <Button onClick={refreshUsers}>Reload users</Button>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={10}>
          <Card title="Current operator">
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="Email">{currentUserEmail}</Descriptions.Item>
              <Descriptions.Item label="Session token"><span className="mono-inline">{maskToken(token)}</span></Descriptions.Item>
              <Descriptions.Item label="Roles">{(currentUser.roles || []).map((role) => <Tag key={role}>{role}</Tag>)}</Descriptions.Item>
              <Descriptions.Item label="Permissions">
                <Space wrap>
                  {(currentUser.permissions || []).map((permission) => <Tag key={permission} color="blue">{permission}</Tag>)}
                </Space>
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col xs={24} xl={7}>
          <Card title="Assign role">
            <Form layout="vertical" onFinish={handleAssignRole}>
              <Form.Item label="User email">
                <Input prefix={<UserOutlined />} value={roleForm.email} onChange={(event) => setRoleForm((prev) => ({ ...prev, email: event.target.value }))} placeholder="peer@example.com" />
              </Form.Item>
              <Form.Item label="Role">
                <Input prefix={<KeyOutlined />} value={roleForm.role} onChange={(event) => setRoleForm((prev) => ({ ...prev, role: event.target.value }))} placeholder="admin" />
              </Form.Item>
              <Button type="primary" htmlType="submit" block>Assign role</Button>
            </Form>
          </Card>
        </Col>
        <Col xs={24} xl={7}>
          <Card title="Delete user">
            <Form layout="vertical" onFinish={handleDeleteUser}>
              <Form.Item label="User ID">
                <Input prefix={<DeleteOutlined />} value={deleteUserId} onChange={(event) => setDeleteUserId(event.target.value)} placeholder="Load users first" />
              </Form.Item>
              <Button danger type="primary" htmlType="submit" block>Delete user</Button>
            </Form>
          </Card>
        </Col>
      </Row>

      <Card title="User inventory">
        <Table columns={userColumns} dataSource={usersRows} pagination={{ pageSize: 6 }} size="middle" scroll={{ x: 860 }} />
      </Card>
    </Space>
  );
}

function ThreatSection({ metrics, eventRows, riskRows, refreshThreats }) {
  const eventColumns = [
    { title: 'Email', dataIndex: 'email', key: 'email' },
    { title: 'IP', dataIndex: 'ip', key: 'ip' },
    { title: 'Type', dataIndex: 'type', key: 'type' },
    { title: 'Outcome', dataIndex: 'outcome', key: 'outcome', render: (outcome) => <Tag color={outcome === 'success' ? 'green' : outcome === 'blocked' ? 'red' : 'gold'}>{outcome}</Tag> },
    { title: 'Risk', dataIndex: 'risk', key: 'risk' },
    { title: 'Time', dataIndex: 'createdAt', key: 'createdAt' },
  ];

  const riskColumns = [
    { title: 'Email', dataIndex: 'email', key: 'email' },
    { title: 'Risk level', dataIndex: 'level', key: 'level', render: (level) => <Tag color={level === 'high' ? 'red' : level === 'medium' ? 'gold' : 'green'}>{level}</Tag> },
    { title: 'Risk score', dataIndex: 'score', key: 'score' },
    { title: 'Failed', dataIndex: 'failedAttempts', key: 'failedAttempts' },
    { title: 'Blocked', dataIndex: 'blockedAttempts', key: 'blockedAttempts' },
    { title: 'Recent IPs', dataIndex: 'recentIps', key: 'recentIps' },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div className="module-header">
        <div>
          <Text className="section-label">Threat monitoring</Text>
          <Title level={3}>IP-aware security events, anomaly outcomes, and dynamic risk scores</Title>
        </div>
        <Button onClick={refreshThreats}>Refresh threats</Button>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} md={8}><Card><Statistic title="Recent security events" value={metrics.securityEvents} prefix={<BellOutlined />} /></Card></Col>
        <Col xs={24} md={8}><Card><Statistic title="High risk users" value={metrics.highRisk} prefix={<RadarChartOutlined />} /></Card></Col>
        <Col xs={24} md={8}><Card><Statistic title="Suspicious users now" value={metrics.suspiciousNow} prefix={<SecurityScanOutlined />} /></Card></Col>
      </Row>

      <Card title="Security events feed">
        <Table columns={eventColumns} dataSource={eventRows} pagination={{ pageSize: 8 }} size="small" scroll={{ x: 920 }} />
      </Card>
      <Card title="Risk summary">
        <Table columns={riskColumns} dataSource={riskRows} pagination={{ pageSize: 8 }} size="small" scroll={{ x: 920 }} />
      </Card>
    </Space>
  );
}

function AuditSection({ auditRows, response, refreshAudit }) {
  const activityColumns = [
    { title: 'Action', dataIndex: 'action', key: 'action' },
    { title: 'Target', dataIndex: 'target', key: 'target' },
    { title: 'Status', dataIndex: 'status', key: 'status', render: (status) => <Tag color={status === 'success' ? 'green' : 'red'}>{status}</Tag> },
    { title: 'Detail', dataIndex: 'detail', key: 'detail', ellipsis: true },
    { title: 'Time', dataIndex: 'createdAt', key: 'createdAt' },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div className="module-header">
        <div>
          <Text className="section-label">Audit and activity</Text>
          <Title level={3}>Who did what, when it happened, and how the system recorded it</Title>
        </div>
        <Button onClick={refreshAudit}>Refresh audit</Button>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card title="Audit log feed">
            <Table columns={activityColumns} dataSource={auditRows} pagination={{ pageSize: 8 }} size="small" scroll={{ x: 980 }} />
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title="Latest API payload">
            <pre className="json-block">{response}</pre>
          </Card>
        </Col>
      </Row>
    </Space>
  );
}

function GovernanceSection({ dataGovernance, usersRows, eventRows }) {
  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div className="module-header">
        <div>
          <Text className="section-label">Data governance and privacy</Text>
          <Title level={3}>How the platform minimises exposure of personal data and protects access evidence</Title>
        </div>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={10}>
          <Card title="Governance defaults">
            <List size="small" dataSource={governanceItems(dataGovernance)} renderItem={(item) => <List.Item>{item}</List.Item>} />
          </Card>
        </Col>
        <Col xs={24} xl={14}>
          <Card title="Masked data examples">
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="User email example">{usersRows[0]?.email || 'No user data loaded yet'}</Descriptions.Item>
              <Descriptions.Item label="Last IP example">{usersRows[0]?.lastIp || 'No IP data loaded yet'}</Descriptions.Item>
              <Descriptions.Item label="Event email example">{eventRows[0]?.email || 'No event data loaded yet'}</Descriptions.Item>
              <Descriptions.Item label="Event IP example">{eventRows[0]?.ip || 'No event data loaded yet'}</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
      </Row>
    </Space>
  );
}

function FutureSection() {
  const extensionCards = [
    {
      title: 'Network Security Extension',
      items: ['Traffic anomaly detection', 'North-south and east-west event ingestion', 'Firewall policy visibility'],
    },
    {
      title: 'Vulnerability Intelligence',
      items: ['Asset-to-risk correlation', 'CVE prioritisation', 'Application dependency risk feed'],
    },
    {
      title: 'Incident Response Workflow',
      items: ['Operator acknowledgement queue', 'Escalation workflow', 'Containment playbooks'],
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <div className="module-header">
        <div>
          <Text className="section-label">Future extension</Text>
          <Title level={3}>Reserved platform surface for broader cybersecurity operations</Title>
        </div>
      </div>
      <Row gutter={[16, 16]}>
        {extensionCards.map((card) => (
          <Col xs={24} lg={8} key={card.title}>
            <Card title={card.title} extra={<Tag color="blue">Future</Tag>}>
              <List size="small" dataSource={card.items} renderItem={(item) => <List.Item>{item}</List.Item>} />
            </Card>
          </Col>
        ))}
      </Row>
    </Space>
  );
}

function AppDashboard({
  activeModule,
  setActiveModule,
  message,
  response,
  currentUser,
  currentUserEmail,
  systemSummary,
  usersPayload,
  metrics,
  token,
  handleRefreshAll,
  handleRefreshUsers,
  handleRefreshThreats,
  handleRefreshAudit,
  handleAssignRole,
  handleDeleteUser,
  handleSignOut,
  roleForm,
  setRoleForm,
  deleteUserId,
  setDeleteUserId,
}) {
  const usersRows = parseUsers(usersPayload);
  const auditRows = parseAuditRows(systemSummary);
  const eventRows = parseEventRows(systemSummary);
  const riskRows = parseRiskRows(systemSummary);
  const dataGovernance = systemSummary?.data_governance || usersPayload?.data_governance || null;

  const menuItems = [
    { key: 'overview', icon: <CloudServerOutlined />, label: 'Administrator Dashboard' },
    { key: 'identity', icon: <TeamOutlined />, label: 'Identity and Access' },
    { key: 'threats', icon: <RadarChartOutlined />, label: 'Threat Monitoring' },
    { key: 'audit', icon: <AuditOutlined />, label: 'Audit and Activity' },
    { key: 'governance', icon: <BgColorsOutlined />, label: 'Data Governance' },
    { key: 'future', icon: <GlobalOutlined />, label: 'Future Extension' },
  ];

  const moduleTitle = {
    overview: 'Administrator Dashboard',
    identity: 'Identity and Access',
    threats: 'Threat Monitoring',
    audit: 'Audit and Activity',
    governance: 'Data Governance',
    future: 'Future Extension',
  }[activeModule];

  let content = null;
  if (activeModule === 'overview') {
    content = <OverviewSection metrics={metrics} systemSummary={systemSummary} riskRows={riskRows} auditRows={auditRows} eventRows={eventRows} refreshAll={handleRefreshAll} />;
  } else if (activeModule === 'identity') {
    content = <IdentitySection currentUser={currentUser} currentUserEmail={currentUserEmail} token={token} usersRows={usersRows} roleForm={roleForm} setRoleForm={setRoleForm} deleteUserId={deleteUserId} setDeleteUserId={setDeleteUserId} handleAssignRole={handleAssignRole} handleDeleteUser={handleDeleteUser} refreshUsers={handleRefreshUsers} />;
  } else if (activeModule === 'threats') {
    content = <ThreatSection metrics={metrics} eventRows={eventRows} riskRows={riskRows} refreshThreats={handleRefreshThreats} />;
  } else if (activeModule === 'audit') {
    content = <AuditSection auditRows={auditRows} response={response} refreshAudit={handleRefreshAudit} />;
  } else if (activeModule === 'governance') {
    content = <GovernanceSection dataGovernance={dataGovernance} usersRows={usersRows} eventRows={eventRows} />;
  } else {
    content = <FutureSection />;
  }

  return (
    <Layout className="antd-console-layout">
      <Sider width={268} theme="dark" className="antd-console-sider">
        <div className="console-sider-brand">
          <Avatar shape="square" size={40} style={{ background: '#1d4ed8', fontWeight: 700 }}>SA</Avatar>
          <div>
            <div className="section-label section-label--dark">Security Console</div>
            <div className="console-sider-title">SecureAccessAI</div>
          </div>
        </div>
        <div className="console-sider-group">Operate</div>
        <Menu theme="dark" mode="inline" selectedKeys={[activeModule]} items={menuItems} onClick={({ key }) => setActiveModule(key)} />
        <div className="console-sider-footer">
          <Text className="console-sider-copy">Application security platform with reserved space for future network security capability.</Text>
        </div>
      </Sider>
      <Layout>
        <Header className="antd-console-header">
          <div className="header-search-shell">
            <SearchOutlined />
            <span>Search operators, IPs, risk signals, or audit evidence</span>
          </div>
          <Space size={12}>
            <Tag color="blue">{moduleTitle}</Tag>
            <Tag color="green">Authenticated</Tag>
            <Button onClick={handleRefreshAll}>Refresh</Button>
            <Button danger onClick={() => handleSignOut(true)}>Sign Out</Button>
            <Avatar icon={<UserOutlined />} />
          </Space>
        </Header>
        <Content className="antd-console-content">
          <div className="console-page-head compact-gap">
            <div>
              <Text className="section-label">Signed-in workspace</Text>
              <Title level={2} style={{ marginTop: 4, marginBottom: 8 }}>{moduleTitle}</Title>
              <Text type="secondary">Signed in as {currentUserEmail}. The operator is working inside a password-plus-authenticator protected security console.</Text>
            </div>
          </div>
          <Alert type={responseTone(message)} showIcon message={message} style={{ marginBottom: 16 }} />
          {content}
        </Content>
      </Layout>
    </Layout>
  );
}

export function App() {
  const [token, setToken] = useState(getStoredToken());
  const [activeModule, setActiveModule] = useState('overview');
  const [message, setMessage] = useState('Ready.');
  const [response, setResponse] = useState(DEFAULT_RESPONSE_MESSAGE);
  const [currentUser, setCurrentUser] = useState({ roles: [], permissions: [] });
  const [systemSummary, setSystemSummary] = useState(null);
  const [usersPayload, setUsersPayload] = useState({ users: [] });
  const [latestCode, setLatestCode] = useState('No code issued yet.');
  const [metrics, setMetrics] = useState(INITIAL_METRICS);
  const [loginForm, setLoginForm] = useState({ email: bootstrap.demoAdminEmail || '', password: bootstrap.demoAdminPassword || '' });
  const [verifyForm, setVerifyForm] = useState({ challenge_id: '', code: '' });
  const [roleForm, setRoleForm] = useState({ email: '', role: 'admin' });
  const [deleteUserId, setDeleteUserId] = useState('');

  const isDashboardRoute = bootstrap.pageMode === 'dashboard';

  const currentUserEmail = useMemo(() => {
    return currentUser?.email || bootstrap.demoAdminEmail || 'operator@example.com';
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
      void bootstrapDashboard(token);
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

      const users = usersData.users || [];
      const riskUsers = dashboardData.risk_summary?.users || [];
      setMetrics({
        users: users.length,
        adminUsers: users.filter((user) => (user.roles || []).includes('admin')).length,
        securityEvents: dashboardData.system_summary?.security_event_count || 0,
        auditLogs: dashboardData.system_summary?.audit_log_count || 0,
        highRisk: riskUsers.filter((user) => user.risk_level === 'high').length,
        suspiciousNow: riskUsers.filter((user) => (user.risk_score || 0) >= 40).length,
      });
      setMessage('Dashboard ready for ' + meData.email + '.');
      setResponse(prettyJson(dashboardData));
    } catch (error) {
      if (error.status === 401) {
        handleSignOut(false);
        return;
      }
      setMessage('Dashboard load failed (' + String(error.status || 'error') + ').');
      setResponse(prettyJson(error.data || error));
    }
  }

  async function requestLoginCode(payload = loginForm) {
    try {
      const data = await apiRequest('/api/auth/login', { method: 'POST', body: payload });
      setVerifyForm({ challenge_id: data.challenge_id || '', code: '' });
      setLatestCode(data.demo_code || 'No code issued yet.');
      setMessage(data.totp_enabled
        ? 'Password accepted. Enter the current authenticator code to continue.'
        : 'Challenge issued. Complete verification to continue.');
      setResponse(prettyJson(data));
    } catch (error) {
      setMessage('Login failed (' + String(error.status || 'error') + ').');
      setResponse(prettyJson(error.data || error));
    }
  }

  async function handleVerifyCode() {
    try {
      const data = await apiRequest('/api/auth/verify-code', { method: 'POST', body: verifyForm });
      saveToken(data.access_token);
      setToken(data.access_token);
      window.location.assign('/dashboard');
    } catch (error) {
      setMessage('Verification failed (' + String(error.status || 'error') + ').');
      setResponse(prettyJson(error.data || error));
    }
  }

  async function handleRefreshUsers() {
    try {
      const data = await apiRequest('/api/admin/users', { token });
      setUsersPayload(data);
      setMessage('Loaded users.');
      setResponse(prettyJson(data));
      await bootstrapDashboard(token);
    } catch (error) {
      setMessage('User load failed (' + String(error.status || 'error') + ').');
      setResponse(prettyJson(error.data || error));
    }
  }

  async function handleRefreshThreats() {
    try {
      const [events, risk] = await Promise.all([
        apiRequest('/api/admin/security-events', { token }),
        apiRequest('/api/admin/risk-summary', { token }),
      ]);
      setSystemSummary((prev) => ({
        ...(prev || {}),
        recent_security_events: events.events || [],
        risk_summary: risk.risk_summary || prev?.risk_summary,
        data_governance: risk.data_governance || prev?.data_governance,
        system_summary: risk.system_summary || prev?.system_summary,
      }));
      setMessage('Threat monitoring data refreshed.');
      setResponse(prettyJson({ events, risk }));
      await bootstrapDashboard(token);
    } catch (error) {
      setMessage('Threat refresh failed (' + String(error.status || 'error') + ').');
      setResponse(prettyJson(error.data || error));
    }
  }

  async function handleRefreshAudit() {
    try {
      const logs = await apiRequest('/api/admin/audit-logs', { token });
      setSystemSummary((prev) => ({ ...(prev || {}), recent_audit_logs: logs.logs || [], data_governance: logs.data_governance || prev?.data_governance }));
      setMessage('Audit feed refreshed.');
      setResponse(prettyJson(logs));
    } catch (error) {
      setMessage('Audit refresh failed (' + String(error.status || 'error') + ').');
      setResponse(prettyJson(error.data || error));
    }
  }

  async function handleAssignRole() {
    try {
      const data = await apiRequest('/api/rbac/assign-role', { method: 'POST', body: roleForm, token });
      setMessage('Role assignment succeeded.');
      setResponse(prettyJson(data));
      await bootstrapDashboard(token);
    } catch (error) {
      setMessage('Role assignment failed (' + String(error.status || 'error') + ').');
      setResponse(prettyJson(error.data || error));
    }
  }

  async function handleDeleteUser() {
    if (!deleteUserId) return;
    try {
      const data = await apiRequest('/api/admin/users/' + String(deleteUserId), { method: 'DELETE', token });
      setMessage('User deletion succeeded.');
      setResponse(prettyJson(data));
      setDeleteUserId('');
      await bootstrapDashboard(token);
    } catch (error) {
      setMessage('User deletion failed (' + String(error.status || 'error') + ').');
      setResponse(prettyJson(error.data || error));
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
    setCurrentUser({ roles: [], permissions: [] });
    setSystemSummary(null);
    setUsersPayload({ users: [] });
    setMetrics(INITIAL_METRICS);
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
        message={message}
        response={response}
        requestLoginCode={requestLoginCode}
        handleVerifyCode={handleVerifyCode}
      />
    );
  }

  return (
    <AppDashboard
      activeModule={activeModule}
      setActiveModule={setActiveModule}
      message={message}
      response={response}
      currentUser={currentUser}
      currentUserEmail={currentUserEmail}
      systemSummary={systemSummary}
      usersPayload={usersPayload}
      metrics={metrics}
      token={token}
      handleRefreshAll={() => bootstrapDashboard(token)}
      handleRefreshUsers={handleRefreshUsers}
      handleRefreshThreats={handleRefreshThreats}
      handleRefreshAudit={handleRefreshAudit}
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
