import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { toast } from 'sonner';
import { Shield, Lock, Mail, User, Eye, EyeOff, AlertTriangle } from 'lucide-react';
import { motion } from 'framer-motion';

const LoginPage = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: ''
  });
  
  const { login, register } = useAuth();
  const navigate = useNavigate();

  // Seraph AI Logo URL
  const logoUrl = "https://customer-assets.emergentagent.com/job_securityshield-17/artifacts/4jbqdhyd_ChatGPT%20Image%20Feb%2010%2C%202026%2C%2009_07_51%20AM.png";

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (isLogin) {
        await login(formData.email, formData.password);
        toast.success('Seraphic access granted. Welcome, Guardian.');
      } else {
        await register(formData.email, formData.password, formData.name);
        toast.success('Guardian registered. Seraphic access granted.');
      }
      navigate('/dashboard');
    } catch (error) {
      const message = error.response?.data?.detail || 'Authentication failed';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex" style={{ backgroundColor: '#0C1020' }}>
      {/* Left Panel - Decorative */}
      <div className="hidden lg:flex lg:w-1/2 relative overflow-hidden">
        <div 
          className="absolute inset-0 bg-cover bg-center"
          style={{
            backgroundImage: 'url(https://images.unsplash.com/photo-1680992046626-418f7e910589?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDk1Nzl8MHwxfHNlYXJjaHwxfHxzZXJ2ZXIlMjByb29tJTIwZGFyayUyMGJsdWUlMjBsaWdodHN8ZW58MHx8fHwxNzcwNjQ0NjkxfDA&ixlib=rb-4.1.0&q=85)'
          }}
        />
        <div className="absolute inset-0" style={{ background: 'linear-gradient(to right, #0C1020, rgba(12, 16, 32, 0.8), transparent)' }} />
        <div className="absolute inset-0" style={{ background: 'linear-gradient(to top, #0C1020, transparent, transparent)' }} />
        
        {/* Content overlay */}
        <div className="relative z-10 p-12 flex flex-col justify-end">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="flex items-center gap-4 mb-6">
              <div className="w-16 h-16 rounded-xl overflow-hidden" style={{ 
                background: 'linear-gradient(135deg, rgba(253, 230, 138, 0.3), rgba(56, 189, 248, 0.3))',
                boxShadow: '0 0 40px rgba(253, 230, 138, 0.4), 0 0 80px rgba(56, 189, 248, 0.2)',
                border: '1px solid rgba(253, 230, 138, 0.3)'
              }}>
                <img src={logoUrl} alt="Seraph AI" className="w-full h-full object-cover" />
              </div>
              <div>
                <h1 className="font-mono font-bold text-3xl tracking-wider" style={{ color: '#FDE68A', textShadow: '0 0 20px rgba(253, 230, 138, 0.5)' }}>SERAPH AI</h1>
                <p className="text-sm" style={{ color: '#A5F3FC' }}>Divine Cyber Guardian</p>
              </div>
            </div>
            
            <h2 className="text-3xl font-mono font-bold mb-4" style={{ color: '#E0E7FF' }}>
              Seraphic Watch<br />
              <span style={{ color: '#38BDF8' }}>Defense Platform</span>
            </h2>
            <p style={{ color: '#A5F3FC' }} className="max-w-md">
              Divine protection against autonomous AI agents, polymorphic malware, 
              and advanced cyber threats. Omniscient behavioral analysis with celestial precision.
            </p>
            
            {/* Stats */}
            <div className="grid grid-cols-3 gap-4 mt-8">
              {[
                { label: 'Threats Blocked', value: '2.4M+' },
                { label: 'AI Scans/Day', value: '150K+' },
                { label: 'Response Time', value: '<10ms' },
              ].map((stat, i) => (
                <div key={i} className="backdrop-blur rounded-lg p-3" style={{ 
                  backgroundColor: 'rgba(18, 24, 51, 0.8)', 
                  border: '1px solid rgba(56, 189, 248, 0.2)' 
                }}>
                  <p className="text-2xl font-mono font-bold" style={{ color: '#FDE68A' }}>{stat.value}</p>
                  <p className="text-xs" style={{ color: '#A5F3FC' }}>{stat.label}</p>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </div>

      {/* Right Panel - Login Form */}
      <div className="flex-1 flex items-center justify-center p-8">
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.4 }}
          className="w-full max-w-md"
        >
          {/* Mobile Logo */}
          <div className="lg:hidden flex items-center gap-3 mb-8">
            <div className="w-12 h-12 rounded-xl overflow-hidden" style={{ 
              background: 'linear-gradient(135deg, rgba(253, 230, 138, 0.2), rgba(56, 189, 248, 0.2))',
              border: '1px solid rgba(253, 230, 138, 0.3)'
            }}>
              <img src={logoUrl} alt="Seraph AI" className="w-full h-full object-cover" />
            </div>
            <div>
              <h1 className="font-mono font-bold text-xl" style={{ color: '#FDE68A' }}>SERAPH AI</h1>
              <p className="text-xs" style={{ color: '#A5F3FC' }}>Seraphic Watch</p>
            </div>
          </div>

          <div className="backdrop-blur-xl rounded-xl p-8" style={{ 
            backgroundColor: 'rgba(18, 24, 51, 0.9)', 
            border: '1px solid rgba(56, 189, 248, 0.2)',
            boxShadow: '0 0 40px rgba(56, 189, 248, 0.1)'
          }}>
            <div className="mb-6">
              <h2 className="text-xl font-mono font-bold mb-1" style={{ color: '#E0E7FF' }}>
                {isLogin ? 'Guardian Access' : 'Register Guardian'}
              </h2>
              <p className="text-sm" style={{ color: '#A5F3FC' }}>
                {isLogin 
                  ? 'Enter credentials to access the Seraphic console'
                  : 'Register for Seraphic guardian access'}
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              {!isLogin && (
                <div className="space-y-2">
                  <Label htmlFor="name" className="text-sm" style={{ color: '#A5F3FC' }}>Name</Label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: '#38BDF8' }} />
                    <Input
                      id="name"
                      type="text"
                      placeholder="Your name"
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="pl-10"
                      style={{ 
                        backgroundColor: '#0C1020', 
                        borderColor: 'rgba(56, 189, 248, 0.3)', 
                        color: '#E0E7FF' 
                      }}
                      data-testid="register-name-input"
                      required={!isLogin}
                    />
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="email" className="text-slate-300 text-sm">Email</Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <Input
                    id="email"
                    type="email"
                    placeholder="analyst@defense.io"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    className="pl-10 bg-slate-950 border-slate-800 text-white placeholder:text-slate-600 focus:border-blue-500 focus:ring-blue-500/20"
                    data-testid="login-email-input"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="password" className="text-slate-300 text-sm">Password</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <Input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="••••••••"
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                    className="pl-10 pr-10 bg-slate-950 border-slate-800 text-white placeholder:text-slate-600 focus:border-blue-500 focus:ring-blue-500/20"
                    data-testid="login-password-input"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <Button
                type="submit"
                disabled={loading}
                className="w-full bg-blue-600 hover:bg-blue-500 text-white font-mono shadow-glow-blue btn-tactical"
                data-testid="login-submit-btn"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Authenticating...
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    <Lock className="w-4 h-4" />
                    {isLogin ? 'Access System' : 'Create Account'}
                  </span>
                )}
              </Button>
            </form>

            <div className="mt-6 pt-6 border-t border-slate-800">
              <p className="text-center text-sm text-slate-400">
                {isLogin ? "Don't have an account?" : 'Already have an account?'}
                <button
                  onClick={() => setIsLogin(!isLogin)}
                  className="ml-2 text-blue-400 hover:text-blue-300 font-medium"
                  data-testid="toggle-auth-mode"
                >
                  {isLogin ? 'Register' : 'Login'}
                </button>
              </p>
            </div>

            {/* Security Notice */}
            <div className="mt-4 p-3 bg-amber-500/10 border border-amber-500/20 rounded flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 flex-shrink-0" />
              <p className="text-xs text-amber-200/80">
                This is a classified defense system. Unauthorized access attempts are logged and monitored.
              </p>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default LoginPage;
