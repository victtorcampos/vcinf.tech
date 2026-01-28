"use client";

import { useState, useEffect } from "react";
import { DashboardSidebar } from "@/components/dashboard/DashboardSidebar";
import { DashboardNavbar } from "@/components/dashboard/DashboardNavbar";
import { cn } from "@/lib/utils";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [isMobile, setIsMobile] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const checkMobile = () => {
      const mobile = window.innerWidth < 768;
      setIsMobile(mobile);
      if (mobile) {
        setSidebarOpen(false);
      } else {
        setSidebarOpen(true);
      }
    };

    checkMobile();
    window.addEventListener("resize", checkMobile);
    return () => window.removeEventListener("resize", checkMobile);
  }, []);

  const toggleSidebar = () => setSidebarOpen(!sidebarOpen);

  // Prevent hydration mismatch
  if (!mounted) {
    return null;
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Sidebar */}
      <DashboardSidebar
        isOpen={sidebarOpen}
        toggle={toggleSidebar}
        className={cn(
          isMobile && "shadow-2xl",
          isMobile && !sidebarOpen && "-translate-x-full w-64", // Hide off-screen on mobile
          isMobile && sidebarOpen && "translate-x-0 w-64"      // Show full width on mobile
        )}
      />

      {/* Main Content Wrapper */}
      <div
        className={cn(
          "flex min-h-screen flex-col transition-all duration-300 ease-in-out",
          !isMobile && (sidebarOpen ? "ml-64" : "ml-16") // Adjust margin on desktop
        )}
      >
        <DashboardNavbar onToggleSidebar={toggleSidebar} userName="Admin User" />
        
        <main className="flex-1 overflow-x-hidden p-6">
          {children}
        </main>
      </div>

      {/* Mobile Overlay */}
      {isMobile && sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 backdrop-blur-sm transition-opacity"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}
    </div>
  );
}
