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
      "mt-4",
      className
    )}>
      <div className="max-w-7xl mx-auto px-6 py-4">
        {/* Social Links and Coffee Button - Centered */}
        <div className="flex flex-col items-center space-y-4">
          <div className="flex items-center space-x-6">
            {socialLinks.map((link) => {
              const IconComponent = link.icon;
              return (
                <a
                  key={link.name}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={cn(
                    "flex items-center justify-center w-10 h-10 rounded-xl",
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

          {/* Buy Me a Coffee */}
          <button
            onClick={handleBuyMeACoffee}
            className={cn(
              "flex items-center space-x-2 px-4 py-2 rounded-xl",
              "bg-gradient-to-r from-amber-500 to-orange-500",
              "text-white font-medium text-sm",
              "transition-all duration-300 transform hover:scale-105",
              "shadow-lg hover:shadow-xl hover:shadow-amber-500/25",
              "border border-amber-400/30"
            )}
          >
            <Coffee className="w-4 h-4" />
            <span>Buy me a coffee</span>
          </button>
        </div>

        {/* Copyright */}
        <div className="mt-6 pt-4 border-t border-sidebar-border/30 text-center">
          <p className="text-sm text-sidebar-foreground/50">
            © 2025 CyberLab. Educational platform for cybersecurity learning.
          </p>
        </div>
      </div>
    </footer>
  );
};