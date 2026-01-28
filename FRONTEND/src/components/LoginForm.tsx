"use client";

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { User, Lock, Loader2 } from 'lucide-react';

export default function LoginForm() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      // Chamamos nossa própria rota interna do Next.js (Proxy)
      // Ela vai cuidar de pegar o token e setar o cookie HttpOnly
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (response.ok) {
        // Não precisamos salvar nada no localStorage
        // O cookie vcinf_token já foi definido pelo servidor
        router.push('/dashboard');
        router.refresh(); // Força atualização para o middleware reconhecer o cookie
      } else {
        const errorData = await response.json();
        setError(errorData.message || 'Credenciais inválidas. Tente novamente.');
      }
    } catch (error) {
      setError('Não foi possível conectar ao servidor. Verifique sua conexão.');
    }

    setIsLoading(false);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="relative">
        <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
        <input
          type="text"
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Usuário"
          required
          className="w-full pl-10 pr-4 py-2 border rounded-md bg-transparent focus:ring-primary focus:border-primary"
        />
      </div>
      <div className="relative">
        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
        <input
          type="password"
          id="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Senha"
          required
          className="w-full pl-10 pr-4 py-2 border rounded-md bg-transparent focus:ring-primary focus:border-primary"
        />
      </div>

      {error && (
        <p className="text-sm text-red-500 text-center">{error}</p>
      )}

      <button
        type="submit"
        disabled={isLoading}
        className="w-full flex justify-center items-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-[var(--primary)] hover:bg-[var(--secondary)] focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary disabled:opacity-50"
      >
        {isLoading ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            <span>Entrando...</span>
          </>
        ) : (
          'Entrar'
        )}
      </button>
    </form>
  );
}
