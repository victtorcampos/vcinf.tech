import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { username, password } = body;

    // A URL deve ser a do serviço Docker interno se estiver rodando no server-side, 
    // mas aqui estamos rodando no contexto do Next.js que pode estar no host ou container.
    // Usamos variável de ambiente ou fallback para localhost:8080 (backend)

    const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080' ;

    const res = await fetch(`${API_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });


    if (!res.ok) {
      // Se backend retornar erro, repassamos
      const errorData = await res.json().catch(() => ({}));
      return NextResponse.json(
        { message: errorData.message || 'Login falhou' },
        { status: res.status }
      );
    }



    const data = await res.json();
    const token = data.token;

    // Criamos a resposta
    const response = NextResponse.json({ success: true });

    // Definimos o cookie HttpOnly
    response.cookies.set({
      name: 'vcinf_token',
      value: token,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      path: '/',
      maxAge: 60 * 60 * 24, // 1 dia em segundos (ajuste conforme seu JWT expiration)
      sameSite: 'strict',
    });

    return response;

  } catch (error) {
    console.error('Erro no login proxy:', error);
    return NextResponse.json(
      { message: 'Erro interno no servidor de autenticação' },
      { status: 500 }
    );
  }
}
