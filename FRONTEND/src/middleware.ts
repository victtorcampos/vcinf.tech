import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Rotas que são públicas e não requerem autenticação
const publicRoutes = ['/login', '/cadastro', '/'];

export function middleware(request: NextRequest) {
  // 1. Tenta ler o cookie de autenticação (HttpOnly)
  const token = request.cookies.get('vcinf_token')?.value;
  
  // 2. Verifica qual rota o usuário está tentando acessar
  const { pathname } = request.nextUrl;
  const isPublicRoute = publicRoutes.some(route => pathname === route || pathname.startsWith('/login'));

  // CASO 1: Usuário NÃO logado tentando acessar rota protegida (Dashboard, Perfil, etc)
  if (!token && !isPublicRoute) {
    // Redireciona para login e anexa a URL original para redirecionar de volta depois
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('callbackUrl', pathname);
    return NextResponse.redirect(loginUrl);
  }

  // CASO 2: Usuário JÁ logado tentando acessar página de login/cadastro
  // (Melhoria de UX: joga direto pro dashboard)
  if (token && isPublicRoute && pathname !== '/') {
     return NextResponse.redirect(new URL('/dashboard', request.url));
  }

  // CASO 3: Tudo certo, permite a requisição passar
  return NextResponse.next();
}

// Configuração do Matcher: Onde o middleware vai rodar?
// Excluímos: api routes (geralmente tem auth própria), arquivos estáticos (_next, imagens, favicon)
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
