import React from "react";
import { Toaster as Sonner, toast } from "sonner";

const Toaster = ({ ...props }) => {
  return (
    <Sonner
      theme="dark"
      className="toaster group"
      toastOptions={{
        classNames: {
          toast:
            "group toast group-[.toaster]:bg-[#121212] group-[.toaster]:text-[#f5f2f0] group-[.toaster]:border-[rgba(255,255,255,0.25)] group-[.toaster]:shadow-lg",
          description: "group-[.toast]:text-[rgba(255,255,255,0.85)]",
          actionButton:
            "group-[.toast]:bg-[#00FFD1] group-[.toast]:text-[#000000]",
          cancelButton:
            "group-[.toast]:bg-[#0f1518] group-[.toast]:text-[rgba(255,255,255,0.85)]",
        },
      }}
      {...props}
    />
  );
};

export { Toaster, toast };
