import { useState } from 'react';
import { Shield, ArrowRight, User } from 'lucide-react';
import { loginUser } from '../services/api.service';

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
    <div className="flex justify-center items-center min-h-screen bg-slate-50 w-full">
      <div className="bg-white border border-slate-200 rounded-lg p-10 w-full max-w-md shadow-md">
        <div className="text-center mb-8">
          <div className="inline-flex justify-center items-center w-16 h-16 bg-blue-50 text-blue-600 rounded-full mb-4">
            <Shield size={36} />
          </div>
          <h2 className="m-0 text-2xl font-bold text-slate-900">Welcome to Mini-SIEM</h2>
          <p className="mt-2 text-sm text-slate-500">Security Information & Event Management</p>
        </div>

        <form className="flex flex-col gap-5" onSubmit={handleLogin}>
          {error && <div className="bg-red-50 text-red-700 p-3 rounded-md text-sm text-center">{error}</div>}

          <div className="flex flex-col gap-2">
            <label className="font-medium text-sm text-slate-900">Email</label>
            <input
              type="email"
              className="px-3 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-500 transition-colors"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@siem.local"
              required
            />
          </div>

          <div className="flex flex-col gap-2">
            <label className="font-medium text-sm text-slate-900">Password</label>
            <input
              type="password"
              className="px-3 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-500 transition-colors"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>

          <button type="submit" className="flex justify-center items-center gap-2 w-full py-3 bg-blue-600 text-white border-none text-base font-medium rounded-md cursor-pointer hover:bg-blue-700 transition-colors" disabled={loading}>
            {loading ? 'Authenticating...' : 'Sign In'}
            {!loading && <ArrowRight size={18} />}
          </button>
        </form>

        <div className="flex items-center text-center my-6 before:content-[''] before:flex-1 before:border-b before:border-slate-200 after:content-[''] after:flex-1 after:border-b after:border-slate-200">
          <span className="px-3 text-slate-500 text-sm font-medium">OR</span>
        </div>

        <button 
          className="flex justify-center items-center gap-2 w-full py-3 bg-white text-slate-900 border border-slate-300 text-base font-medium rounded-md cursor-pointer hover:bg-slate-50 transition-colors" 
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
