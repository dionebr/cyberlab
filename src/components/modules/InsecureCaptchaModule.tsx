import { Shield } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Badge } from "../ui/badge";

interface InsecureCaptchaModuleProps {
  difficulty: string;
}

export const InsecureCaptchaModule = ({ difficulty }: InsecureCaptchaModuleProps) => {
  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-4 mb-8">
        <div className="p-3 bg-accent/10 rounded-lg">
          <Shield className="h-8 w-8 text-accent" />
        </div>
        <div>
          <h1 className="text-3xl font-bold">Insecure Captcha Challenge</h1>
          <p className="text-muted-foreground">Backend implementation completed</p>
          <Badge variant="outline" className="mt-2">
            Difficulty: {difficulty}
          </Badge>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Backend Implementation Complete</CardTitle>
        </CardHeader>
        <CardContent>
          <p>The Insecure Captcha module backend is fully implemented with all API endpoints working.</p>
        </CardContent>
      </Card>
    </div>
  );
};
