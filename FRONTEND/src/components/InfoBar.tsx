'use client';

import { MapPin, Clock, Phone } from 'lucide-react';

export function InfoBar() {
  return (
    <section 
      className="py-16"
      style={{ 
        backgroundColor: 'var(--primary)',
      }}
      data-testid="info-bar-section"
    >
      <div className="max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid md:grid-cols-3 gap-8 text-center md:text-left">
          {/* Location */}
          <div className="flex flex-col md:flex-row items-center md:items-start gap-4">
            <div 
              className="w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: 'color-mix(in srgb, var(--primary-foreground) 20%, transparent)' }}
            >
              <MapPin size={24} style={{ color: 'var(--primary-foreground)' }} />
            </div>
            <div>
              <h3 
                className="font-semibold text-lg mb-1"
                style={{ color: 'var(--primary-foreground)' }}
              >
                Atendendo Sorriso/MT e região
              </h3>
              <p 
                className="text-sm opacity-80"
                style={{ color: 'var(--primary-foreground)' }}
              >
                Av. Natalino João Brescansin, Nº 375, Centro Sul
              </p>
            </div>
          </div>

          {/* Hours */}
          <div className="flex flex-col md:flex-row items-center md:items-start gap-4">
            <div 
              className="w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: 'color-mix(in srgb, var(--primary-foreground) 20%, transparent)' }}
            >
              <Clock size={24} style={{ color: 'var(--primary-foreground)' }} />
            </div>
            <div>
              <h3 
                className="font-semibold text-lg mb-1"
                style={{ color: 'var(--primary-foreground)' }}
              >
                Horário de Atendimento
              </h3>
              <p 
                className="text-sm opacity-80"
                style={{ color: 'var(--primary-foreground)' }}
              >
                Segunda a Sexta: 8h às 18h
              </p>
            </div>
          </div>

          {/* Contact */}
          <div className="flex flex-col md:flex-row items-center md:items-start gap-4">
            <div 
              className="w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: 'color-mix(in srgb, var(--primary-foreground) 20%, transparent)' }}
            >
              <Phone size={24} style={{ color: 'var(--primary-foreground)' }} />
            </div>
            <div>
              <h3 
                className="font-semibold text-lg mb-1"
                style={{ color: 'var(--primary-foreground)' }}
              >
                Fale Conosco
              </h3>
              <p 
                className="text-sm opacity-80"
                style={{ color: 'var(--primary-foreground)' }}
              >
                (66) 3544-1504 • contato@vcinf.tech
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
