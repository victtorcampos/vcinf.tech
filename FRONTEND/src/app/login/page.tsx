
import LoginForm from '@/components/LoginForm';

export default function LoginPage() {
  return ( 
    <div className="flex items-center justify-center min-h-screen bg-background">
      <div className="w-full max-w-md p-8 space-y-8 bg-card rounded-lg shadow-lg">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-foreground">Área do Cliente</h1>
          <p className="text-muted-foreground">
            Acesse sua conta para gerenciar seus serviços.
          </p>
        </div>
        <LoginForm />
      </div>
    </div>
  );
}

