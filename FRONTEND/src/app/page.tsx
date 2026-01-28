import { Navbar } from "@/components/Navbar";
import Hero from "@/components/Hero";
import Services from "@/components/Services";
import InfoBar from "@/components/InfoBar";
import Footer from "@/components/Footer";

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
