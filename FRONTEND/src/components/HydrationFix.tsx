'use client';

import { useEffect } from 'react';

export function HydrationFix() {
  useEffect(() => {
    // Este código roda APENAS no cliente, depois da hidratação
    const theme = localStorage.getItem('theme') || 
      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', theme);
  }, []);

  return null;
}
