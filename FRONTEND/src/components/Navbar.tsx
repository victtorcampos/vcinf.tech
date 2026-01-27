'use client';

import Link from 'next/link';
import { useState } from 'react';
import { ThemeToggle } from './ThemeToggle';
import { LogoIcon } from './LogoIcon';

export function Navbar() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const navLinks = [
    { href: '#home', label: 'Home' },
    { href: '#servicos', label: 'Serviços' },
    { href: '#loja', label: 'Loja Online' },
    { href: '#noticias', label: 'Notícias' },
    { href: '#contato', label: 'Contato' },
  ];

  return (
    <nav 
      className="fixed w-full z-20 top-0 start-0 border-b"
      style={{ 
        backgroundColor: 'var(--background)', 
        borderColor: 'color-mix(in srgb, var(--secondary) 30%, transparent)' 
      }}
      data-testid="main-navbar"
    >
      <div className="max-w-screen-xl flex flex-wrap items-center justify-between mx-auto p-4">
        {/* Logo */}
        <Link 
          href="/" 
          className="flex items-center space-x-3"
          onClick={() => setIsMenuOpen(false)}
          data-testid="logo-link"
        >
          <LogoIcon className="h-8 w-auto" />
          <span 
            className="self-center text-xl font-semibold whitespace-nowrap"
            style={{ color: 'var(--primary)' }}
          >
            VCINF TECH
          </span>
        </Link>

        {/* CTA Button + Theme Toggle + Mobile Menu Button */}
        <div className="flex md:order-2 items-center gap-2">
          <ThemeToggle />
          
          <Link
            href="/login"
            className="hidden md:inline-flex items-center justify-center px-4 py-2 text-sm font-medium rounded-lg transition-colors focus:ring-4 focus:outline-none"
            style={{ 
              backgroundColor: 'var(--primary)', 
              color: 'var(--primary-foreground)',
            }}
            data-testid="cta-button"
            onMouseEnter={(e) => e.currentTarget.style.opacity = '0.9'}
            onMouseLeave={(e) => e.currentTarget.style.opacity = '1'}
          >
            Área do Cliente
          </Link>

          {/* Mobile menu button */}
          <button
            type="button"
            className="inline-flex items-center p-2 w-10 h-10 justify-center text-sm rounded-lg md:hidden focus:outline-none focus:ring-2 transition-colors"
            style={{ 
              color: 'var(--secondary)',
            }}
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            aria-controls="navbar-sticky"
            aria-expanded={isMenuOpen}
            data-testid="mobile-menu-toggle"
          >
            <span className="sr-only">{isMenuOpen ? 'Fechar menu' : 'Abrir menu'}</span>
            {isMenuOpen ? (
              <svg className="w-5 h-5" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            ) : (
              <svg className="w-5 h-5" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <path stroke="currentColor" strokeLinecap="round" strokeWidth="2" d="M5 7h14M5 12h14M5 17h14"/>
              </svg>
            )}
          </button>
        </div>

        {/* Navigation Links */}
        <div 
          className={`items-center justify-between w-full md:flex md:w-auto md:order-1 ${isMenuOpen ? 'block' : 'hidden'}`}
          id="navbar-sticky"
        >
          <ul 
            className="flex flex-col p-4 md:p-0 mt-4 font-medium border rounded-lg md:space-x-8 md:flex-row md:mt-0 md:border-0"
            style={{ 
              borderColor: 'color-mix(in srgb, var(--secondary) 30%, transparent)',
              backgroundColor: isMenuOpen ? 'color-mix(in srgb, var(--secondary) 10%, var(--background))' : 'transparent'
            }}
          >
            {navLinks.map((link, index) => (
              <li key={link.label}>
                <Link
                  href={link.href}
                  className="block py-2 px-3 rounded md:p-0 transition-colors"
                  style={{ 
                    color: index === 0 ? 'var(--primary)' : 'var(--foreground)',
                  }}
                  onClick={() => setIsMenuOpen(false)}
                  data-testid={`nav-link-${index}`}
                  onMouseEnter={(e) => e.currentTarget.style.color = 'var(--primary)'}
                  onMouseLeave={(e) => e.currentTarget.style.color = index === 0 ? 'var(--primary)' : 'var(--foreground)'}
                >
                  {link.label}
                </Link>
              </li>
            ))}
            
            {/* Mobile CTA */}
            <li className="md:hidden mt-4">
              <Link
                href="/login"
                className="block w-full text-center px-4 py-2 text-sm font-medium rounded-lg transition-colors"
                style={{ 
                  backgroundColor: 'var(--primary)', 
                  color: 'var(--primary-foreground)',
                }}
                onClick={() => setIsMenuOpen(false)}
                data-testid="mobile-cta-button"
              >
                Área do Cliente
              </Link>
            </li>
          </ul>
        </div>
      </div>
    </nav>
  );
}
