import { Hero } from '@/components/Hero';
import { Services } from '@/components/Services';
import { InfoBar } from '@/components/InfoBar';
import { Footer } from '@/components/Footer';

export default function Home() {
  return (
    <>
      <Hero />
      <Services />
      <InfoBar />
      <Footer />
    </>
  );
}
