import { Github, Linkedin, Youtube, Coffee } from 'lucide-react';
import { cn } from '@/lib/utils';

interface FooterProps {
  className?: string;
}

export const Footer = ({ className }: FooterProps) => {
  const handleBuyMeACoffee = () => {
    window.open('https://www.buymeacoffee.com/dionelima', '_blank', 'noopener,noreferrer');
  };

  const socialLinks = [
    {
      name: 'GitHub',
      icon: Github,
      url: 'https://github.com/dionebr',
      color: 'hover:text-gray-300'
    },
    {
      name: 'LinkedIn',
      icon: Linkedin,
      url: 'https://linkedin.com/in/dionelima',
      color: 'hover:text-blue-400'
    },
    {
      name: 'YouTube',
      icon: Youtube,
      url: 'https://youtube.com/@dionelima',
      color: 'hover:text-red-400'
    }
  ];

  return (
    <footer className={cn(
      "border-t border-sidebar-border bg-sidebar/95 backdrop-blur-sm",
      className
    )}>
      <div className="max-w-7xl mx-auto px-6 py-4">
        <div className="flex flex-col md:flex-row items-center justify-between space-y-4 md:space-y-0">
          
          {/* Left Section - Creator Credits */}
          <div className="flex items-center space-x-3">
            <div className="creator-hover footer-creator relative px-4 py-3 rounded-xl">
              <img 
                src="/perfil.webp"
                alt="Dione Lima" 
                className="creator-photo"
              />
              <div className="creator-info">
                <p className="text-sidebar-foreground/70 text-sm">
                  Created by
                </p>
                <p className="text-sidebar-foreground font-semibold text-lg gradient-text">
                  Dione Lima
                </p>
              </div>
            </div>
          </div>

          {/* Center Section - Social Links */}
          <div className="flex items-center space-x-6 social-links">
            {socialLinks.map((link) => {
              const IconComponent = link.icon;
              return (
                <a
                  key={link.name}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={cn(
                    "social-icon flex items-center justify-center w-10 h-10 rounded-xl",
                    "bg-sidebar-accent/50 border border-sidebar-border text-sidebar-foreground/60",
                    "transition-all duration-300 transform hover:scale-110",
                    "hover:bg-sidebar-accent hover:border-sidebar-border",
                    "hover:shadow-lg hover:shadow-current/20",
                    link.color
                  )}
                  title={link.name}
                >
                  <IconComponent className="w-5 h-5" />
                </a>
              );
            })}
          </div>

          {/* Right Section - Buy Me a Coffee */}
          <button
            onClick={handleBuyMeACoffee}
            className={cn(
              "coffee-button flex items-center space-x-2 px-4 py-2 rounded-xl relative",
              "bg-gradient-to-r from-amber-500 to-orange-500",
              "hover:from-amber-400 hover:to-orange-400",
              "text-white font-medium text-sm",
              "transition-all duration-300 transform hover:scale-105",
              "shadow-lg hover:shadow-xl hover:shadow-amber-500/25",
              "border border-amber-400/30"
            )}
          >
            <div className="coffee-steam"></div>
            <Coffee className="w-4 h-4" />
            <span>Buy me a coffee</span>
          </button>
        </div>

        {/* Bottom Section - Additional Info */}
        <div className="mt-4 pt-4 border-t border-sidebar-border/30">
          <div className="flex flex-col md:flex-row items-center justify-between space-y-2 md:space-y-0 text-sm text-sidebar-foreground/50">
            <div className="flex items-center space-x-4">
              <span>© 2025 CyberLab Professional</span>
              <span className="hidden md:inline">•</span>
              <span className="flex items-center space-x-1">
                <span>Educational platform for</span>
                <span className="text-sidebar-primary font-medium">Cybersecurity</span>
              </span>
            </div>
            
            <div className="flex items-center space-x-2 text-xs">
              <div className="w-2 h-2 bg-green-400 rounded-full status-glow" />
              <span>Intentional vulnerabilities for learning</span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};