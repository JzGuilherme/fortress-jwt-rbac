import React from 'react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'outline';
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', ...props }, ref) => {
    const variants: Record<NonNullable<ButtonProps['variant']>, string> = {
      primary:
        'bg-emerald-500 text-slate-950 hover:bg-emerald-400 font-semibold shadow-sm shadow-emerald-950/50',
      secondary:
        'bg-slate-800 text-slate-100 hover:bg-slate-700 border border-slate-700 font-medium',
      danger: 'bg-rose-600 text-white hover:bg-rose-500 font-semibold',
      outline:
        'bg-transparent text-slate-200 border border-slate-700 hover:bg-slate-800/70 font-medium',
    };

    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm transition-colors disabled:opacity-45 disabled:pointer-events-none',
          variants[variant],
          className
        )}
        {...props}
      />
    );
  }
);
Button.displayName = 'Button';

export const Badge: React.FC<{
  children: React.ReactNode;
  tone?: 'emerald' | 'amber' | 'rose' | 'purple' | 'slate';
}> = ({ children, tone = 'slate' }) => {
  const tones = {
    emerald: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    amber: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    rose: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
    purple: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
    slate: 'bg-slate-800 text-slate-300 border-slate-700',
  };

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold tracking-wide',
        tones[tone]
      )}
    >
      {children}
    </span>
  );
};
