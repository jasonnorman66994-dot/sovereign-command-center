import './App.css';
import { AnimatePresence, motion } from 'framer-motion';
import { useEffect, useState } from 'react';
import { Activity, ShieldAlert, Radar, Database } from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8055';
const staggerContainer = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.15, delayChildren: 0.3 },
  },
};

const stagger_item = {
  hidden: { y: 20, opacity: 0 },
  show: { y: 0, opacity: 1 },
};

async function checkAuth() {
  const token = sessionStorage.getItem('shadow.access_token') || localStorage.getItem('token') || '';
  if (!token) {
    return false;
  }

  try {
    const resp = await fetch(`${API_BASE}/health/notifications`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return resp.ok;
  } catch {
    return false;
  }
}

function LoginOverlay({ onAuthSuccess }) {
  const [status, setStatus] = useState('AUTH CHECK REQUIRED');

  async function verifyNow() {
    setStatus('CHECKING...');
    const ok = await checkAuth();
    if (ok) {
      setStatus('AUTHORIZED');
      onAuthSuccess();
    } else {
      setStatus('DENIED - LOGIN VIA DASHBOARD OIDC');
    }
  }

  return (
    <motion.div
      className="login-overlay"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <motion.div
        className="login-card"
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
      >
        <h2>Sovereign Identity Gate</h2>
        <p className="muted">Status: {status}</p>
        <button onClick={verifyNow}>Run Auth Check</button>
      </motion.div>
    </motion.div>
  );
}

function TelemetryCard({ title, icon: Icon, data }) {
  return (
    <div className="telemetry-card">
      <h3>
        <Icon size={15} /> {title}
      </h3>
      <div className="data-stream">{data}</div>
    </div>
  );
}

function SystemEntrance({ isAuth, liveArp, nodeData, pcapLogs, sentinelStatus }) {
  if (!isAuth) {
    return null;
  }

  return (
    <motion.div
      initial={{ opacity: 0, filter: 'blur(20px)' }}
      animate={{ opacity: 1, filter: 'blur(0px)' }}
      transition={{ duration: 1.2 }}
      className="dashboard-wrapper"
    >
      <header className="monokai-grid-header">[ AUTHENTICATED: OPERATOR LVL 3 ]</header>

      <motion.div variants={staggerContainer} initial="hidden" animate="show" className="hud-layout">
        <motion.div variants={stagger_item}>
          <TelemetryCard title="ARP DETECTOR" icon={ShieldAlert} data={liveArp} />
        </motion.div>
        <motion.div variants={stagger_item}>
          <TelemetryCard title="NETWORK MAP" icon={Radar} data={nodeData} />
        </motion.div>
        <motion.div variants={stagger_item}>
          <TelemetryCard title="FORENSIC AUDIT" icon={Database} data={pcapLogs} />
        </motion.div>
        <motion.div variants={stagger_item}>
          <TelemetryCard title="SENTINEL STATUS" icon={Activity} data={sentinelStatus} />
        </motion.div>
      </motion.div>
    </motion.div>
  );
}

function DashboardHUD() {
  return (
    <SystemEntrance
      isAuth={true}
      liveArp="No spoofing signals detected in last sweep."
      nodeData="3 businesses loaded • Company_Alpha active assets mapped"
      pcapLogs="Forensic endpoints online • audit and pcap retrieval healthy"
      sentinelStatus="Collector and websocket bridge operational"
    />
  );
}

function App() {
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth().then((res) => {
      setIsAuthorized(res);
      setLoading(false);
    });
  }, []);

  if (loading) {
    return (
      <div className="monokai-bg loading-screen">
        <div>INITIALIZING HUD...</div>
      </div>
    );
  }

  return (
    <div className="monokai-bg">
      <AnimatePresence mode="wait">
        {!isAuthorized ? (
          <LoginOverlay onAuthSuccess={() => setIsAuthorized(true)} />
        ) : (
          <DashboardHUD />
        )}
      </AnimatePresence>
    </div>
  );
}

export default App;
