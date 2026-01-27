'use client';

import Link from 'next/link';

export function Hero() {
  return (
    <section 
      className="relative min-h-[90vh] flex items-center justify-center overflow-hidden"
      style={{ backgroundColor: 'var(--background)' }}
      data-testid="hero-section"
    >
      {/* Background Pattern */}
      <div className="absolute inset-0 overflow-hidden">
        <div 
          className="absolute top-1/4 -left-20 w-96 h-96 rounded-full blur-3xl opacity-20"
          style={{ backgroundColor: 'var(--primary)' }}
        />
        <div 
          className="absolute bottom-1/4 -right-20 w-80 h-80 rounded-full blur-3xl opacity-15"
          style={{ backgroundColor: 'var(--secondary)' }}
        />
        <div 
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full blur-3xl opacity-10"
          style={{ backgroundColor: 'var(--primary)' }}
        />
        {/* Grid Pattern */}
        <div 
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `linear-gradient(var(--foreground) 1px, transparent 1px), linear-gradient(90deg, var(--foreground) 1px, transparent 1px)`,
            backgroundSize: '60px 60px'
          }}
        />
      </div>

      {/* Content */}
      <div className="relative z-10 max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        {/* Badge */}
        <div 
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium mb-8"
          style={{ 
            backgroundColor: 'color-mix(in srgb, var(--primary) 15%, transparent)',
            color: 'var(--primary)'
          }}
        >
          <span className="relative flex h-2 w-2">
            <span 
              className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75"
              style={{ backgroundColor: 'var(--primary)' }}
            />
            <span 
              className="relative inline-flex rounded-full h-2 w-2"
              style={{ backgroundColor: 'var(--primary)' }}
            />
          </span>
          Sorriso/MT e Região
        </div>

        {/* Headline */}
        <h1 
          className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6 max-w-4xl mx-auto leading-tight"
          style={{ color: 'var(--foreground)' }}
        >
          Soluções Completas em{' '}
          <span style={{ color: 'var(--primary)' }}>Hardware</span> e{' '}
          <span style={{ color: 'var(--primary)' }}>Inteligência Fiscal</span>
        </h1>

        {/* Subheadline */}
        <p 
          className="text-lg sm:text-xl max-w-2xl mx-auto mb-10 leading-relaxed"
          style={{ color: 'var(--secondary)' }}
        >
          Manutenção especializada, infraestrutura de redes e assessoria contábil 
          exclusiva para desenvolvedores de software.
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
          <Link
            href="#contato"
            className="inline-flex items-center justify-center px-8 py-4 text-base font-semibold rounded-lg transition-all duration-300 hover:scale-105 hover:shadow-lg"
            style={{ 
              backgroundColor: 'var(--primary)', 
              color: 'var(--primary-foreground)',
              boxShadow: '0 4px 14px color-mix(in srgb, var(--primary) 40%, transparent)'
            }}
            data-testid="hero-cta-primary"
          >
            Falar com Especialista
            <svg className="w-5 h-5 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
            </svg>
          </Link>
          
          <Link
            href="#servicos"
            className="inline-flex items-center justify-center px-8 py-4 text-base font-semibold rounded-lg transition-all duration-300 border-2"
            style={{ 
              borderColor: 'var(--secondary)',
              color: 'var(--secondary)',
              backgroundColor: 'transparent'
            }}
            data-testid="hero-cta-secondary"
          >
            Conhecer Serviços
          </Link>
        </div>

        {/* Stats */}
        <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-8 max-w-3xl mx-auto">
          {[
            { value: '10+', label: 'Anos de Experiência' },
            { value: '500+', label: 'Clientes Atendidos' },
            { value: '24h', label: 'Suporte Técnico' },
            { value: '100%', label: 'Satisfação' },
          ].map((stat, index) => (
            <div key={index} className="text-center">
              <div 
                className="text-3xl sm:text-4xl font-bold mb-1"
                style={{ color: 'var(--primary)' }}
              >
                {stat.value}
              </div>
              <div 
                className="text-sm"
                style={{ color: 'var(--secondary)' }}
              >
                {stat.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Scroll Indicator */}
      <div className="absolute bottom-8 left-1/2 -translate-x-1/2 animate-bounce">
        <svg 
          className="w-6 h-6" 
          fill="none" 
          stroke="currentColor" 
          viewBox="0 0 24 24"
          style={{ color: 'var(--secondary)' }}
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
        </svg>
      </div>
    </section>
  );
}
