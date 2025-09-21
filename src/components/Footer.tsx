import { Github, Linkedin, Youtube, Coffee } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useEffect, useRef } from 'react';

interface FooterProps {
  className?: string;
}

export const Footer = ({ className }: FooterProps) => {
  const terminalRef = useRef<HTMLDivElement>(null);

  const handleBuyMeACoffee = () => {
    window.open('https://www.buymeacoffee.com/dionelima', '_blank', 'noopener,noreferrer');
  };

  const handleTerminalClick = () => {
    if (terminalRef.current) {
      terminalRef.current.classList.add('clicked');
      
      // Remove class after animation
      setTimeout(() => {
        if (terminalRef.current) {
          terminalRef.current.classList.remove('clicked');
        }
      }, 3000);
    }
  };

  // Auto-start typing animation after component mounts
  useEffect(() => {
    const timer = setTimeout(() => {
      const typingElement = document.getElementById('typing-command');
      if (typingElement) {
        typingElement.style.animationPlayState = 'running';
      }
    }, 1000);

    return () => clearTimeout(timer);
  }, []);

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
      "border-t border-sidebar-border bg-sidebar/95 backdrop-blur-sm overflow-visible",
      "mt-4", // Added 1cm margin-top to lower the footer
      className
    )}>
      <div className="max-w-7xl mx-auto px-0 py-0 overflow-visible" style={{ paddingTop: '0.1.rem', paddingBottom: '0.1.rem' }}>
        <div className="flex flex-col md:flex-row items-center justify-between space-y-2 md:space-y-0">
          
          {/* Left Section - Creator Credits with Typing Effect */}
          <div className="flex items-center space-x-3" style={{ marginLeft: '3cm' }}>
            <div 
              ref={terminalRef}
              onClick={handleTerminalClick}
              className="creator-terminal footer-creator relative px-6 py-3.9 rounded-xl overflow-visible bg-gray-900/80 border border-gray-700/50"
            >
              <img 
                src="/perfil.webp"
                alt="Dione Lima" 
                className="creator-photo"
                loading="lazy"
              />
              <div className="creator-info relative z-10">
                <div className="terminal-header mb-2">
                  <div className="flex items-center space-x-2">
                    <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                    <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                    <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                    <span className="text-xs text-sidebar-foreground/50 ml-2">terminal</span>
                  </div>
                </div>
                <div className="terminal-content font-mono text-sm">
                  <div className="flex items-center text-green-400 mb-1">
                    <span className="text-cyan-400">$</span>
                    <span className="ml-2 typing-text" id="typing-command">uname -a | sed 's/.*/Built --dev | Dione Lima/'</span>
                    <span className="cursor-blink">_</span>
                  </div>
                  <div className="text-sidebar-foreground/80 result-text opacity-0">
                    Built --dev | Dione Lima
                  </div>
                </div>
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
        <div className="mt-1 pt-1 border-t border-sidebar-border/30" style={{ marginTop: '0.25rem', paddingTop: '0.25rem' }}>
          <div className="flex flex-col md:flex-row items-center justify-between space-y-1 md:space-y-0 text-sm text-sidebar-foreground/50">
            <div className="flex items-center space-x-4" style={{ marginLeft: '3cm' }}>
          
              <span className="flex items-center space-x-1">
              </span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};