"use client";

import { cn } from "@/lib/utils";
import { 
  LayoutDashboard, 
  Settings, 
  ChevronLeft, 
  ChevronRight,
  Menu,
  Home
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";
import { LogoIcon } from "@/components/LogoIcon";

interface SidebarProps {
  className?: string;
  isOpen: boolean;
  toggle: () => void;
}

export function DashboardSidebar({ className, isOpen, toggle }: SidebarProps) {
  const pathname = usePathname();

  const menuItems = [
    {
      title: "Dashboard",
      icon: LayoutDashboard,
      href: "/dashboard",
      active: pathname === "/dashboard",
    },
    {
      title: "Configurações",
      icon: Settings,
      href: "/dashboard/settings",
      active: pathname === "/dashboard/settings",
    },
  ];

  return (
    <aside
      className={cn(
        "fixed left-0 top-0 z-40 h-screen border-r bg-background transition-all duration-300 ease-in-out",
        isOpen ? "w-64" : "w-16",
        className
      )}
    >
      <div className="flex h-16 items-center justify-between px-4">
        <Link href="/" className={cn("flex items-center gap-2 font-bold transition-all", !isOpen && "justify-center w-full")}>
           <div className="h-8 w-8 text-primary">
             <LogoIcon />
           </div>
           {isOpen && <span className="text-xl text-primary truncate">vcinf.tech</span>}
        </Link>
      </div>
      
      <Separator />

      <div className="flex flex-col gap-2 p-3">
        {menuItems.map((item) => (
          <Button
            key={item.href}
            variant={item.active ? "secondary" : "ghost"}
            className={cn(
              "justify-start transition-all", 
              !isOpen && "justify-center px-2",
              item.active && "bg-secondary text-secondary-foreground"
            )}
            asChild
          >
            <Link href={item.href}>
              <item.icon className={cn("h-5 w-5", isOpen && "mr-2")} />
              {isOpen && <span>{item.title}</span>}
            </Link>
          </Button>
        ))}
      </div>

      <div className="absolute bottom-4 left-0 right-0 px-3">
         <Button 
            variant="outline" 
            size="icon" 
            className="w-full mt-auto" 
            onClick={toggle}
         >
            {isOpen ? <ChevronLeft className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
         </Button>
      </div>
    </aside>
  );
}
