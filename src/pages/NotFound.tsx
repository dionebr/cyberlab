import { useLocation } from "react-router-dom";
import { useEffect } from "react";
import { useLanguage } from "../hooks/useLanguage";
import { Button } from "../components/ui/button";
import { Home, AlertTriangle } from "lucide-react";

const NotFound = () => {
  const location = useLocation();
  const { t } = useLanguage();

  useEffect(() => {
    console.error("404 Error: User attempted to access non-existent route:", location.pathname);
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="text-center space-y-6 p-8">
        <div className="flex justify-center mb-6">
          <div className="p-4 bg-gradient-danger rounded-2xl shadow-danger">
            <AlertTriangle className="h-16 w-16 text-white" />
          </div>
        </div>
        
        <h1 className="text-6xl font-bold bg-gradient-danger bg-clip-text text-transparent">
          404
        </h1>
        
        <h2 className="text-2xl font-semibold text-foreground">
          {t("notfound.title")}
        </h2>
        
        <p className="text-xl text-muted-foreground max-w-md mx-auto">
          {t("notfound.description")}
        </p>
        
        <Button 
          asChild
          size="lg" 
          className="bg-gradient-cyber hover:shadow-glow transition-all duration-300 text-lg px-8 py-6"
        >
          <a href="/">
            <Home className="mr-2 h-5 w-5" />
            {t("notfound.return_home")}
          </a>
        </Button>
      </div>
    </div>
  );
};

export default NotFound;
