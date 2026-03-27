import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider } from 'antd';
import 'antd/dist/reset.css';
import { App } from './App.jsx';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#1677ff',
          colorSuccess: '#16a34a',
          colorWarning: '#d97706',
          colorError: '#dc2626',
          borderRadius: 10,
          fontFamily: 'Inter, system-ui, sans-serif',
          colorBgLayout: '#f5f7fb',
          colorBgContainer: '#ffffff',
        },
        components: {
          Layout: {
            siderBg: '#0b1f5e',
            triggerBg: '#0b1f5e',
            headerBg: '#ffffff',
          },
          Menu: {
            darkItemBg: '#0b1f5e',
            darkSubMenuItemBg: '#0b1f5e',
            darkItemSelectedBg: '#173da6',
            darkItemHoverBg: '#123280',
          },
          Card: {
            headerFontSize: 15,
          },
        },
      }}
    >
      <App />
    </ConfigProvider>
  </React.StrictMode>
);
