import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { SidebarProvider } from "@/components/ui/sidebar";
import { ThemeProvider } from "./contexts/ThemeContext";
import { SecurityLevelProvider } from "./contexts/SecurityLevelContext";
import Index from "./pages/Index";
import NotFound from "./pages/NotFound";
import Learn from "./pages/Learn";
import Challenge from "./pages/Challenge";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider>
      <SecurityLevelProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter
            future={{
              v7_startTransition: true,
              v7_relativeSplatPath: true
            }}
          >
            <SidebarProvider defaultOpen={true}>
              <div className="min-h-screen flex w-full">
                <Routes>
                  <Route path="/" element={<Index />} />
                  <Route path="/learn" element={<Learn />} />
                  <Route path="/learn/:category" element={<Learn />} />
                  <Route path="/learn/:category/:level" element={<Learn />} />
                  <Route path="/challenges/:moduleId" element={<Challenge />} />
                  <Route path="/challenges/:moduleId/:level" element={<Challenge />} />
                  {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
                  <Route path="*" element={<NotFound />} />
                </Routes>
              </div>
            </SidebarProvider>
          </BrowserRouter>
        </TooltipProvider>
      </SecurityLevelProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
