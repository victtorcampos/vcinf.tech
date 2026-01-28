import { Footer } from "@/components/Footer";
import { Hero } from "@/components/Hero";
import { InfoBar } from "@/components/InfoBar";
import { Navbar } from "@/components/Navbar";
import { Services } from "@/components/Services";

export default function Home() {
  return (
    <>
      <Navbar />
      <main className="flex min-h-screen flex-col items-center justify-between">
        <Hero />
        <Services />
        <InfoBar />
        <Footer />
      </main>
    </>
  );
}
