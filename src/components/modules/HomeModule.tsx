import { FlaskConical, Target, Globe, Layers, AlertTriangle, Info } from "lucide-react";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Alert, AlertDescription } from "../ui/alert";
import { useLanguage } from "../../hooks/useLanguage";
import { DeveloperSection } from "../DeveloperSection";

export const HomeModule = () => {
  const { t } = useLanguage();

  const features = [
    {
      icon: Target,
      title: t("home.features.interactive"),
      description: t("home.features.interactive_desc"),
      color: "danger",
    },
    {
      icon: Globe,
      title: t("home.features.multilingual"),
      description: t("home.features.multilingual_desc"),
      color: "info",
    },
    {
      icon: Layers,
      title: t("home.features.difficulty"),
      description: t("home.features.difficulty_desc"),
      color: "success",
    },
  ];

  const colorClasses = {
    danger: "bg-red-100 text-red-600 dark:bg-red-900/20 dark:text-red-400",
    info: "bg-blue-100 text-blue-600 dark:bg-blue-900/20 dark:text-blue-400", 
    success: "bg-green-100 text-green-600 dark:bg-green-900/20 dark:text-green-400"
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      {/* Hero Section */}
      <div className="text-center space-y-6 py-12">
        <div className="flex justify-center mb-6">
          <div className="p-6 bg-card/50 border border-primary/20 rounded-3xl shadow-lg">
            <FlaskConical className="h-20 w-20 text-primary" />
          </div>
        </div>
        
        <h1 className="text-4xl md:text-6xl font-bold text-foreground">
          {t("home.title")}
        </h1>
        
        <p className="text-xl text-muted-foreground max-w-4xl mx-auto leading-relaxed">
          {t("home.description")}
        </p>

        <Button 
          size="lg" 
          className="bg-gradient-cyber hover:shadow-glow transition-all duration-300 text-lg px-8 py-6"
        >
          {t("home.get_started")}
        </Button>
      </div>

      {/* General Instructions */}
      <Card className="bg-gradient-to-r from-card to-card/50 border-primary/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            <Info className="h-5 w-5 text-primary" />
            {t("home.general_instructions")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground leading-relaxed">
            {t("home.general_instructions_content")}
          </p>
        </CardContent>
      </Card>

      {/* Developer Section */}
      <DeveloperSection className="my-8" />

      {/* Features Grid */}
      <div className="grid md:grid-cols-3 gap-6">
        {features.map((feature, index) => {
          const Icon = feature.icon;
          return (
            <Card 
              key={index} 
              className="group hover:shadow-cyber transition-all duration-300 hover:-translate-y-1"
            >
              <CardHeader className="text-center pb-2">
                <div className={`mx-auto p-3 rounded-lg ${colorClasses[feature.color as keyof typeof colorClasses]} group-hover:shadow-glow transition-all duration-300`}>
                  <Icon className="h-8 w-8" />
                </div>
                <CardTitle className="text-lg">{feature.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground text-center">
                  {feature.description}
                </p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Warning Section */}
      <Alert className="border-warning bg-warning/10">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          <div className="space-y-2">
            <p className="font-semibold text-warning">{t("home.warning")}</p>
            <p className="text-sm">{t("home.warning_content")}</p>
          </div>
        </AlertDescription>
      </Alert>

      {/* Stats Section */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6 py-8">
        {[
          { number: "11+", label: "Vulnerability Modules" },
          { number: "4", label: "Security Levels" },
          { number: "3", label: "Languages" },
          { number: "∞", label: "Learning Opportunities" },
        ].map((stat, index) => (
          <div key={index} className="text-center space-y-2">
            <div className="text-3xl font-bold text-primary">{stat.number}</div>
            <div className="text-sm text-muted-foreground">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Disclaimer */}
      <Card className="bg-gradient-to-r from-muted/50 to-muted/20 border-muted">
        <CardHeader>
          <CardTitle className="text-lg">{t("home.disclaimer")}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground leading-relaxed">
            {t("home.disclaimer_content")}
          </p>
        </CardContent>
      </Card>

      {/* Getting Started */}
      <Card className="bg-gradient-to-r from-card to-card/50 border-primary/20">
        <CardContent className="p-8">
          <div className="text-center space-y-4">
            <h3 className="text-2xl font-semibold">Ready to Start Learning?</h3>
            <p className="text-muted-foreground">
              Choose a vulnerability module from the sidebar to begin your hands-on security education journey.
            </p>
            <div className="flex flex-wrap justify-center gap-4 pt-4">
              <Button variant="outline" className="border-primary text-primary hover:bg-primary hover:text-primary-foreground">
                SQL Injection
              </Button>
              <Button variant="outline" className="border-warning text-warning hover:bg-warning hover:text-warning-foreground">
                XSS
              </Button>
              <Button variant="outline" className="border-danger text-danger hover:bg-danger hover:text-danger-foreground">
                Command Injection
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};