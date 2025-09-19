import { useParams } from "react-router-dom";
import { Header } from "../components/Header";
import { AppSidebar } from "../components/AppSidebar";
import { ModuleContent } from "../components/ModuleContent";
import { SidebarInset } from "@/components/ui/sidebar";
import { useLanguage } from "../hooks/useLanguage";
import { useSecurityLevelContext } from "../contexts/SecurityLevelContext";

const Challenge = () => {
  const { moduleId, level } = useParams<{ moduleId: string; level: string }>();
  const { language } = useLanguage();
  const { securityLevel } = useSecurityLevelContext();

  // Use the global security level instead of URL level
  const effectiveLevel = securityLevel;
  const effectiveModule = moduleId || "home";

  return (
    <>
      <AppSidebar />
      <SidebarInset>
        <Header />
        <main className="flex-1 overflow-auto">
          <div className="p-6">
            <ModuleContent 
              activeModule={effectiveModule}
              difficulty={effectiveLevel}
              language={language}
            />
          </div>
        </main>
      </SidebarInset>
    </>
  );
};

export default Challenge;