import React, { useState, useEffect } from 'react';

interface DeveloperSectionProps {
  className?: string;
}

export const DeveloperSection: React.FC<DeveloperSectionProps> = ({ className = "" }) => {
  const [displayText, setDisplayText] = useState("");
  const [showPhoto, setShowPhoto] = useState(false);
  const [isTyping, setIsTyping] = useState(false);
  const [currentCycle, setCurrentCycle] = useState(0);
  
  const fullText = "Developed by Dione Lima - Cybersecurity Specialist & Full Stack Developer";
  
  useEffect(() => {
    let typeTimer: number;
    let photoTimer: number;
    let cycleTimer: number;
    
    const typeText = () => {
      setIsTyping(true);
      setShowPhoto(false);
      setDisplayText("");
      
      let currentIndex = 0;
      typeTimer = window.setInterval(() => {
        if (currentIndex <= fullText.length) {
          setDisplayText(fullText.slice(0, currentIndex));
          currentIndex++;
        } else {
          clearInterval(typeTimer);
          setIsTyping(false);
          
          // Show photo after typing completes with a slight delay
          photoTimer = window.setTimeout(() => {
            setShowPhoto(true);
            setDisplayText("");
            
            // Hide photo after 5 seconds and start cycle again
            cycleTimer = window.setTimeout(() => {
              setCurrentCycle(prev => prev + 1);
              typeText();
            }, 5000);
          }, 1500);
        }
      }, 60); // Slightly slower typing for better readability
    };
    
    // Start initial typing
    typeText();
    
    return () => {
      clearInterval(typeTimer);
      clearTimeout(photoTimer);
      clearTimeout(cycleTimer);
    };
  }, []);
  
  return (
    <div className={`relative bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 rounded-xl p-6 shadow-2xl border border-gray-700 ${className}`}>
      {/* Terminal Header */}
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-600">
        <div className="flex items-center gap-2">
          <div className="flex gap-2">
            <div className="w-3 h-3 bg-red-500 rounded-full shadow-sm"></div>
            <div className="w-3 h-3 bg-yellow-500 rounded-full shadow-sm"></div>
            <div className="w-3 h-3 bg-green-500 rounded-full shadow-sm"></div>
          </div>
          <div className="text-gray-400 text-sm ml-4 font-mono">CyberLab Terminal</div>
        </div>
        <div className="text-xs text-gray-500 font-mono">
          {new Date().toLocaleTimeString()}
        </div>
      </div>
      
      {/* Content Area */}
      <div className="min-h-[160px] flex items-center justify-center">
        {showPhoto ? (
          <div className="flex flex-col items-center space-y-6 animate-in fade-in-0 duration-700">
            <div className="relative">
              <img 
                src="/perfil.webp" 
                alt="Dione Lima" 
                className="w-28 h-28 rounded-full border-4 border-cyan-400 shadow-2xl object-cover transition-all duration-500 hover:scale-105"
                loading="lazy"
              />
              <div className="absolute -inset-1 rounded-full bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 opacity-20 animate-pulse"></div>
            </div>
            <div className="text-center space-y-2">
              <div className="text-cyan-400 font-bold text-xl tracking-wide">Dione Lima</div>
              <div className="text-gray-300 text-sm max-w-md">
                Cybersecurity Specialist & Full Stack Developer
              </div>
              <div className="flex gap-2 justify-center mt-3">
                <span className="px-2 py-1 bg-cyan-900/30 border border-cyan-500/30 rounded text-xs text-cyan-300">
                  Security Expert
                </span>
                <span className="px-2 py-1 bg-blue-900/30 border border-blue-500/30 rounded text-xs text-blue-300">
                  Full Stack Dev
                </span>
              </div>
            </div>
          </div>
        ) : (
          <div className="w-full space-y-3">
            <div className="flex items-center font-mono">
              <span className="text-cyan-400 mr-3 text-sm">dione@cyberlab:~$</span>
              <span className="text-green-400 text-lg">
                {displayText}
                {isTyping && (
                  <span className="animate-pulse bg-green-400 text-green-400 ml-1 inline-block w-2">|</span>
                )}
              </span>
            </div>
            
            {!isTyping && displayText && (
              <div className="flex items-center gap-2 mt-4 text-gray-400 text-sm font-mono animate-in fade-in-0 duration-1000">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span>System ready • Photo loading...</span>
              </div>
            )}
            
            {isTyping && (
              <div className="flex items-center gap-2 text-gray-500 text-xs font-mono">
                <div className="w-1 h-1 bg-gray-500 rounded-full animate-bounce"></div>
                <div className="w-1 h-1 bg-gray-500 rounded-full animate-bounce" style={{animationDelay: '0.1s'}}></div>
                <div className="w-1 h-1 bg-gray-500 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
                <span className="ml-2">Initializing...</span>
              </div>
            )}
          </div>
        )}
      </div>
      
      {/* Footer Info */}
      <div className="mt-4 pt-3 border-t border-gray-700 flex justify-between items-center text-xs text-gray-500 font-mono">
        <span>CyberLab v2.0 • Production Ready</span>
        <span>Cycle: {currentCycle + 1}</span>
      </div>
    </div>
  );
};