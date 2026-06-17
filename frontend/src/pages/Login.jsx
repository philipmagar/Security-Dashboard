import { useState } from 'react';
import { Shield, ArrowRight, User } from 'lucide-react';
import { loginUser } from '../services/api.service';
import './Login.css';

const Login = ({ onLogin }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await loginUser(email, password);
      onLogin(); // Tell App.jsx we are logged in
    } catch (err) {
      setError(err.message || 'Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = async () => {
    setEmail('admin@siem.local');
    setPassword('Admin@1234');
    setError('');
    setLoading(true);

    try {
      await loginUser('admin@siem.local', 'Admin@1234');
      onLogin();
    } catch (err) {
      setError(err.message || 'Demo login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <div className="login-logo">
            <Shield size={36} className="logo-icon" />
          </div>
          <h2>Welcome to Mini-SIEM</h2>
          <p>Security Information & Event Management</p>
        </div>

        <form className="login-form" onSubmit={handleLogin}>
          {error && <div className="login-error">{error}</div>}

          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@siem.local"
              required
            />
          </div>

          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Authenticating...' : 'Sign In'}
            {!loading && <ArrowRight size={18} />}
          </button>
        </form>

        <div className="login-divider">
          <span>OR</span>
        </div>

        <button 
          className="btn-demo" 
          onClick={handleDemoLogin}
          disabled={loading}
        >
          <User size={18} />
          Login as Demo Admin
        </button>
      </div>
    </div>
  );
};

export default Login;
