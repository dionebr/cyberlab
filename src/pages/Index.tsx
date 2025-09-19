import { useState } from "react";
import { Header } from "../components/Header";
import { AppSidebar } from "../components/AppSidebar";
import { ModuleContent } from "../components/ModuleContent";
import { SidebarInset } from "@/components/ui/sidebar";
import { useLanguage } from "../hooks/useLanguage";
import { useSecurityLevelContext } from "../contexts/SecurityLevelContext";

const Index = () => {
  const [activeModule, setActiveModule] = useState("home");
  const { language } = useLanguage();
  const { securityLevel } = useSecurityLevelContext();

  return (
    <>
      <AppSidebar />
      <SidebarInset>
        <Header />
        <main className="flex-1 overflow-auto">
          <div className="p-6">
            <ModuleContent 
              activeModule={activeModule}
              difficulty={securityLevel}
              language={language}
            />
          </div>
        </main>
      </SidebarInset>
    </>
  );
};

export default Index;