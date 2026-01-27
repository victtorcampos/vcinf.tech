'use client';

import Link from 'next/link';
import { LogoIcon } from './LogoIcon';
import { Phone, Mail, MapPin, Facebook, Instagram, Linkedin } from 'lucide-react';

const footerLinks = {
  services: [
    { label: 'Manutenção de Hardware', href: '#servicos' },
    { label: 'Infraestrutura', href: '#servicos' },
    { label: 'Dev Support', href: '#servicos' },
    { label: 'Desenvolvimento', href: '#servicos' },
  ],
  company: [
    { label: 'Sobre Nós', href: '#' },
    { label: 'Nosso Time', href: '#' },
    { label: 'Carreiras', href: '#' },
    { label: 'Blog', href: '#noticias' },
  ],
};

const socialLinks = [
  { icon: Facebook, href: '#', label: 'Facebook' },
  { icon: Instagram, href: '#', label: 'Instagram' },
  { icon: Linkedin, href: '#', label: 'LinkedIn' },
];

export function Footer() {
  return (
    <footer 
      id="contato"
      style={{ 
        backgroundColor: 'color-mix(in srgb, var(--foreground) 95%, var(--background))',
      }}
      data-testid="footer"
    >
      {/* Main Footer */}
      <div className="max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12">
          {/* Brand Column */}
          <div className="lg:col-span-1">
            <Link href="/" className="flex items-center gap-3 mb-6">
              <LogoIcon className="h-10 w-auto" />
              <span 
                className="text-xl font-bold"
                style={{ color: 'var(--background)' }}
              >
                VCINF TECH
              </span>
            </Link>
            <p 
              className="text-sm mb-6 leading-relaxed opacity-70"
              style={{ color: 'var(--background)' }}
            >
              Soluções completas em hardware e inteligência fiscal para empresas que buscam excelência tecnológica.
            </p>
            {/* Social Links */}
            <div className="flex gap-3">
              {socialLinks.map((social, index) => {
                const Icon = social.icon;
                return (
                  <a
                    key={index}
                    href={social.href}
                    aria-label={social.label}
                    className="w-10 h-10 rounded-lg flex items-center justify-center transition-all duration-300 hover:scale-110"
                    style={{ 
                      backgroundColor: 'color-mix(in srgb, var(--background) 15%, transparent)',
                      color: 'var(--background)'
                    }}
                  >
                    <Icon size={20} />
                  </a>
                );
              })}
            </div>
          </div>

          {/* Services Column */}
          <div>
            <h3 
              className="font-semibold mb-6"
              style={{ color: 'var(--background)' }}
            >
              Serviços
            </h3>
            <ul className="space-y-3">
              {footerLinks.services.map((link, index) => (
                <li key={index}>
                  <Link
                    href={link.href}
                    className="text-sm transition-colors duration-200 hover:opacity-100 opacity-70"
                    style={{ color: 'var(--background)' }}
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Company Column */}
          <div>
            <h3 
              className="font-semibold mb-6"
              style={{ color: 'var(--background)' }}
            >
              Empresa
            </h3>
            <ul className="space-y-3">
              {footerLinks.company.map((link, index) => (
                <li key={index}>
                  <Link
                    href={link.href}
                    className="text-sm transition-colors duration-200 hover:opacity-100 opacity-70"
                    style={{ color: 'var(--background)' }}
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Contact Column */}
          <div>
            <h3 
              className="font-semibold mb-6"
              style={{ color: 'var(--background)' }}
            >
              Contato
            </h3>
            <ul className="space-y-4">
              <li>
                <a 
                  href="tel:+556635441504"
                  className="flex items-center gap-3 text-sm opacity-70 hover:opacity-100 transition-opacity"
                  style={{ color: 'var(--background)' }}
                >
                  <Phone size={18} />
                  (66) 3544-1504
                </a>
              </li>
              <li>
                <a 
                  href="mailto:contato@vcinf.tech"
                  className="flex items-center gap-3 text-sm opacity-70 hover:opacity-100 transition-opacity"
                  style={{ color: 'var(--background)' }}
                >
                  <Mail size={18} />
                  contato@vcinf.tech
                </a>
              </li>
              <li>
                <div 
                  className="flex items-start gap-3 text-sm opacity-70"
                  style={{ color: 'var(--background)' }}
                >
                  <MapPin size={18} className="flex-shrink-0 mt-0.5" />
                  <span>
                    Av. Natalino João Brescansin, Nº 375<br />
                    Centro Sul - Sorriso/MT
                  </span>
                </div>
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Bottom Bar */}
      <div 
        className="border-t"
        style={{ borderColor: 'color-mix(in srgb, var(--background) 15%, transparent)' }}
      >
        <div className="max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <p 
              className="text-sm opacity-60"
              style={{ color: 'var(--background)' }}
            >
              © 2026 VCINF TECH. Todos os direitos reservados.
            </p>
            <div className="flex gap-6">
              <Link 
                href="#" 
                className="text-sm opacity-60 hover:opacity-100 transition-opacity"
                style={{ color: 'var(--background)' }}
              >
                Política de Privacidade
              </Link>
              <Link 
                href="#" 
                className="text-sm opacity-60 hover:opacity-100 transition-opacity"
                style={{ color: 'var(--background)' }}
              >
                Termos de Uso
              </Link>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
