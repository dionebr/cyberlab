import { HomeModule } from "./modules/HomeModule";
import { SQLInjectionModule } from "./modules/SQLInjectionModule";
import { XSSModule } from "./modules/XSSModule";
import { CommandInjectionModule } from "./modules/CommandInjectionModule";
import { CSRFModule } from "./modules/CSRFModule";
import { FileInclusionModule } from "./modules/FileInclusionModule";
import { AuthBypassModule } from "./modules/AuthBypassModule";
import { BruteForceModule } from "./modules/BruteForceModule";
import { FileUploadModule } from "./modules/FileUploadModule";
import { InsecureCaptchaModule } from "./modules/InsecureCaptchaModule";
import { WeakSessionModule } from "./modules/WeakSessionModule";
import { SQLBlindModule } from "./modules/SQLBlindModule";
import { useLanguage } from "../hooks/useLanguage";

interface ModuleContentProps {
  activeModule: string;
  difficulty: string;
  language: string;
}

export const ModuleContent = ({ activeModule, difficulty, language }: ModuleContentProps) => {
  const { t } = useLanguage();

  const renderModule = () => {
    switch (activeModule) {
      case "home":
        return <HomeModule />;
      case "sql-injection":
        return <SQLInjectionModule difficulty={difficulty} />;
      case "xss":
        return <XSSModule difficulty={difficulty} />;
      case "command-injection":
        return <CommandInjectionModule difficulty={difficulty} />;
      case "csrf":
        return <CSRFModule difficulty={difficulty} />;
      case "file-inclusion":
        return <FileInclusionModule difficulty={difficulty} />;
      case "auth-bypass":
        return <AuthBypassModule difficulty={difficulty} />;
      case "brute-force":
        return <BruteForceModule difficulty={difficulty} />;
      case "file-upload":
        return <FileUploadModule difficulty={difficulty} />;
      case "insecure-captcha":
        return <InsecureCaptchaModule difficulty={difficulty} />;
      case "weak-session":
        return <WeakSessionModule difficulty={difficulty} />;
      case "sql-blind":
        return <SQLBlindModule difficulty={difficulty} />;
      default:
        return <HomeModule />;
    }
  };

  return (
    <div className="p-6 min-h-[calc(100vh-4rem)]">
      {renderModule()}
    </div>
  );
};