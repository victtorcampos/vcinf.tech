import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const ProtectedRoute = ({ children, allowedRoles = [] }) => {
  const { user, profile, loading } = useAuth();

  // Mostrar loading enquanto verifica autenticação
  if (loading) {
    return (
      <div className="min-h-screen bg-[#0f1518] flex items-center justify-center">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#00FFD1]"></div>
          <p className="mt-4 text-[rgba(255,255,255,0.85)] text-lg">Carregando...</p>
        </div>
      </div>
    );
  }

  // Redirecionar para login se não autenticado
  if (!user || !profile) {
    return <Navigate to="/login" replace />;
  }

  // Verificar se o role do usuário está permitido
  if (allowedRoles.length > 0 && !allowedRoles.includes(profile.role)) {
    // Redirecionar para o dashboard correto baseado no role
    const roleRedirects = {
      admin: '/admin/dashboard',
      accountant: '/accountant/dashboard',
      client_company: '/client/dashboard',
    };
    return <Navigate to={roleRedirects[profile.role] || '/login'} replace />;
  }

  return children;
};

export default ProtectedRoute;