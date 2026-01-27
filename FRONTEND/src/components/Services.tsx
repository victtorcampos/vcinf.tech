'use client';

import { Monitor, Network, FileCode, Code2 } from 'lucide-react';

const services = [
  {
    icon: Monitor,
    title: 'Manutenção de Hardware',
    description: 'Peças, equipamentos e manutenção especializada para manter sua infraestrutura funcionando perfeitamente.',
    features: ['Diagnóstico técnico', 'Troca de componentes', 'Upgrade de equipamentos']
  },
  {
    icon: Network,
    title: 'Infraestrutura',
    description: 'Redes, Servidores (Proxy, Firewall, BD) configurados com máxima segurança e performance.',
    features: ['Redes corporativas', 'Servidores dedicados', 'Firewall e segurança']
  },
  {
    icon: FileCode,
    title: 'Dev Support',
    description: 'Assessoria fiscal especializada para desenvolvedores e software houses.',
    features: ['Consultoria fiscal', 'Emissão de NF-e', 'Compliance tributário']
  },
  {
    icon: Code2,
    title: 'Desenvolvimento',
    description: 'Apps e softwares sob medida para automatizar e otimizar seu negócio.',
    features: ['Sistemas web', 'Aplicativos mobile', 'Integrações API']
  }
];

export function Services() {
  return (
    <section 
      id="servicos"
      className="py-24"
      style={{ backgroundColor: 'var(--background)' }}
      data-testid="services-section"
    >
      <div className="max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-16">
          <span 
            className="inline-block px-4 py-1.5 rounded-full text-sm font-medium mb-4"
            style={{ 
              backgroundColor: 'color-mix(in srgb, var(--primary) 15%, transparent)',
              color: 'var(--primary)'
            }}
          >
            O que fazemos
          </span>
          <h2 
            className="text-3xl sm:text-4xl font-bold mb-4"
            style={{ color: 'var(--foreground)' }}
          >
            Nossas Especialidades
          </h2>
          <p 
            className="text-lg max-w-2xl mx-auto"
            style={{ color: 'var(--secondary)' }}
          >
            Soluções completas para empresas que precisam de tecnologia confiável e suporte especializado.
          </p>
        </div>

        {/* Services Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {services.map((service, index) => {
            const Icon = service.icon;
            return (
              <div
                key={index}
                className="group relative p-6 rounded-2xl border transition-all duration-300 hover:-translate-y-1"
                style={{ 
                  backgroundColor: 'var(--background)',
                  borderColor: 'color-mix(in srgb, var(--secondary) 20%, transparent)',
                  boxShadow: '0 4px 6px -1px color-mix(in srgb, var(--foreground) 5%, transparent)'
                }}
                data-testid={`service-card-${index}`}
              >
                {/* Icon */}
                <div 
                  className="w-14 h-14 rounded-xl flex items-center justify-center mb-5 transition-transform duration-300 group-hover:scale-110"
                  style={{ 
                    backgroundColor: 'color-mix(in srgb, var(--primary) 15%, transparent)',
                  }}
                >
                  <Icon 
                    size={28} 
                    style={{ color: 'var(--primary)' }}
                  />
                </div>

                {/* Content */}
                <h3 
                  className="text-xl font-semibold mb-3"
                  style={{ color: 'var(--foreground)' }}
                >
                  {service.title}
                </h3>
                <p 
                  className="text-sm mb-4 leading-relaxed"
                  style={{ color: 'var(--secondary)' }}
                >
                  {service.description}
                </p>

                {/* Features */}
                <ul className="space-y-2">
                  {service.features.map((feature, idx) => (
                    <li 
                      key={idx}
                      className="flex items-center text-sm"
                      style={{ color: 'var(--secondary)' }}
                    >
                      <svg 
                        className="w-4 h-4 mr-2 flex-shrink-0" 
                        fill="none" 
                        stroke="currentColor" 
                        viewBox="0 0 24 24"
                        style={{ color: 'var(--primary)' }}
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      {feature}
                    </li>
                  ))}
                </ul>

                {/* Hover Effect Border */}
                <div 
                  className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
                  style={{ 
                    border: '2px solid var(--primary)',
                  }}
                />
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
