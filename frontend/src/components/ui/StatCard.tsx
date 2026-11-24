import React, { useEffect, useState, type ReactNode } from 'react';
import { motion, useMotionValue, useTransform, animate } from 'framer-motion';
import { TrendingUp, TrendingDown } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: number;
  icon: ReactNode;
  loading: boolean;
  subtitle: string;
  trend?: {
    value: number;
    positive: boolean;
  };
}

function AnimatedCounter({ value }: { value: number }) {
  const motionValue = useMotionValue(0);
  const rounded = useTransform(motionValue, (v) => Math.round(v).toLocaleString());
  const [display, setDisplay] = useState('0');

  useEffect(() => {
    const unsubscribe = rounded.on('change', (v) => setDisplay(v));
    const controls = animate(motionValue, value, {
      duration: 1.2,
      ease: 'easeOut',
    });
    return () => {
      controls.stop();
      unsubscribe();
    };
  }, [value, motionValue, rounded]);

  return (
    <motion.span
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
    >
      {display}
    </motion.span>
  );
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  icon,
  loading,
  subtitle,
  trend,
}) => {
  if (loading) {
    return (
      <div className="sentinel-card p-5">
        <div className="flex items-start justify-between mb-3">
          <div className="skeleton h-3 w-24 rounded" />
          <div className="skeleton h-4 w-4 rounded" />
        </div>
        <div className="skeleton h-7 w-20 rounded mb-2" />
        <div className="skeleton h-3 w-32 rounded" />
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="sentinel-card p-5"
    >
      <div className="flex items-start justify-between">
        <span className="text-xs text-[#64748B] uppercase tracking-wider font-semibold mb-3 block">
          {title}
        </span>
        <span className="text-[#64748B]">{icon}</span>
      </div>

      <div className="flex items-baseline gap-2">
        <span className="text-2xl font-bold text-[#F8FAFC]">
          <AnimatedCounter value={value} />
        </span>
        {trend && (
          <span
            className={`text-xs font-semibold flex items-center gap-0.5 ${
              trend.positive ? 'text-[#16A34A]' : 'text-[#DC2626]'
            }`}
          >
            {trend.positive ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
            {Math.abs(trend.value)}%
          </span>
        )}
      </div>

      <span className="text-xs text-[#64748B] mt-1 block">{subtitle}</span>
    </motion.div>
  );
};
