import React from 'react';

interface LogoIconProps {
  className?: string;
}

export function LogoIcon({ className }: LogoIconProps) {
  return (
    <svg viewBox="0 0 200 220" xmlns="http://www.w3.org/2000/svg" className={className || "h-8 w-auto"}>
      {/* poligono */}
      <path fill="#26444f" fillRule="evenodd" d="M 40 20 L 160 20 L 160 125 L 120 160 L 40 94 Z M 75 60 L 120 60 L 120 100 Z"/>
      {/* hexágono */}
      <path fill="#f4f3ef" fillRule="evenodd" d="M 40 94 L 120 160 L 160 125 L 160 185 L 120 185 L 40 120 Z"/>
      {/* triângulo  */}
      <path fill="#355a6c" fillRule="evenodd" d="M 40 120 L 40 185 L 120 185 Z"/>
    </svg>
  );
}
