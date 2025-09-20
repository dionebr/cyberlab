// CSS transition utilities for smooth animations
export const transitions = {
  fast: 'transition-all duration-150 ease-out',
  normal: 'transition-all duration-300 ease-out',
  slow: 'transition-all duration-500 ease-out',
  spring: 'transition-all duration-300 ease-spring',
} as const;

// Animation classes for common effects
export const animations = {
  // Fade animations
  fadeIn: 'animate-in fade-in duration-300',
  fadeOut: 'animate-out fade-out duration-300',
  
  // Slide animations
  slideInLeft: 'animate-in slide-in-from-left duration-300',
  slideInRight: 'animate-in slide-in-from-right duration-300',
  slideInUp: 'animate-in slide-in-from-bottom duration-300',
  slideInDown: 'animate-in slide-in-from-top duration-300',
  
  // Scale animations
  scaleIn: 'animate-in zoom-in duration-300',
  scaleOut: 'animate-out zoom-out duration-300',
  
  // Rotation
  spin: 'animate-spin',
  pulse: 'animate-pulse',
  bounce: 'animate-bounce',
  
  // Hover effects
  hoverScale: 'hover:scale-105 active:scale-95',
  hoverBrightness: 'hover:brightness-110',
  hoverShadow: 'hover:shadow-lg',
} as const;

// Stagger animation utility
export const createStaggerDelay = (index: number, baseDelay = 50) => ({
  animationDelay: `${index * baseDelay}ms`
});

// Progress bar animation
export const animateProgress = (element: HTMLElement, targetWidth: number, duration = 800) => {
  if (!element) return;
  
  element.style.width = '0%';
  element.style.transition = `width ${duration}ms ease-out`;
  
  // Use requestAnimationFrame for smooth animation
  requestAnimationFrame(() => {
    element.style.width = `${targetWidth}%`;
  });
};

// Smooth scroll utility
export const smoothScrollTo = (element: HTMLElement, options?: ScrollIntoViewOptions) => {
  element.scrollIntoView({
    behavior: 'smooth',
    block: 'start',
    inline: 'nearest',
    ...options
  });
};

// Intersection Observer utility for scroll animations
export const createScrollAnimation = (
  callback: (entries: IntersectionObserverEntry[]) => void,
  options?: IntersectionObserverInit
) => {
  return new IntersectionObserver(callback, {
    threshold: 0.1,
    rootMargin: '50px',
    ...options
  });
};

// CSS custom properties for dynamic animations
export const setAnimationProperty = (element: HTMLElement, property: string, value: string) => {
  element.style.setProperty(`--${property}`, value);
};

// Animation event handlers
export const onAnimationEnd = (element: HTMLElement, callback: () => void) => {
  const handleAnimationEnd = () => {
    callback();
    element.removeEventListener('animationend', handleAnimationEnd);
  };
  element.addEventListener('animationend', handleAnimationEnd);
};

// Preload animation classes
export const preloadAnimations = () => {
  const style = document.createElement('style');
  style.textContent = `
    .animate-fade-in {
      animation: fadeIn 0.3s ease-out;
    }
    
    .animate-slide-up {
      animation: slideUp 0.3s ease-out;
    }
    
    .animate-scale-in {
      animation: scaleIn 0.3s ease-out;
    }
    
    .animate-stagger {
      animation: fadeIn 0.3s ease-out;
      animation-fill-mode: both;
    }
    
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    
    @keyframes slideUp {
      from { 
        opacity: 0; 
        transform: translateY(20px); 
      }
      to { 
        opacity: 1; 
        transform: translateY(0); 
      }
    }
    
    @keyframes scaleIn {
      from { 
        opacity: 0; 
        transform: scale(0.9); 
      }
      to { 
        opacity: 1; 
        transform: scale(1); 
      }
    }
    
    @keyframes success-pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.05); }
    }
    
    @keyframes error-shake {
      0%, 100% { transform: translateX(0); }
      10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
      20%, 40%, 60%, 80% { transform: translateX(5px); }
    }
    
    .animate-success {
      animation: success-pulse 0.6s ease-out;
    }
    
    .animate-error {
      animation: error-shake 0.6s ease-out;
    }
  `;
  document.head.appendChild(style);
};

// Initialize animations on page load
if (typeof window !== 'undefined') {
  document.addEventListener('DOMContentLoaded', preloadAnimations);
}