import { ShieldAlert, ArrowLeft } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export function NotFoundPage() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-[#0E1117] flex flex-col items-center justify-center p-6 text-center">
      <div className="w-16 h-16 rounded-2xl bg-[#16A34A]/10 border border-[#16A34A]/25 flex items-center justify-center mb-6 text-[#16A34A] animate-pulse">
        <ShieldAlert className="w-8 h-8" />
      </div>

      <h1 className="text-6xl font-bold text-[#F8FAFC] tracking-tight">404</h1>
      <h2 className="text-lg font-semibold text-[#94A3B8] mt-2">Requested resource not found.</h2>
      <p className="text-xs text-[#64748B] mt-1 max-w-xs leading-relaxed">
        The route you are trying to access does not exist or requires different authorization privileges.
      </p>

      <button
        onClick={() => navigate('/dashboard')}
        className="sentinel-btn-primary mt-8 flex items-center gap-2 px-4 py-2 text-xs"
      >
        <ArrowLeft className="w-4 h-4" />
        Return to Overview
      </button>

      <div className="mt-16 text-[11px] text-[#475569] flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-[#16A34A]" />
        Protected by Syvora Security Platform.
      </div>
    </div>
  );
}
