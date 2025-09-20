import { useEffect, useRef, useState, useCallback } from 'react';

// Hook for intersection observer
export const useIntersectionObserver = (
  options: IntersectionObserverInit = {}
) => {
  const [isVisible, setIsVisible] = useState(false);
  const [hasBeenVisible, setHasBeenVisible] = useState(false);
  const elementRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const element = elementRef.current;
    if (!element) return;

    const observer = new IntersectionObserver(([entry]) => {
      setIsVisible(entry.isIntersecting);
      if (entry.isIntersecting && !hasBeenVisible) {
        setHasBeenVisible(true);
      }
    }, {
      threshold: 0.1,
      rootMargin: '50px',
      ...options
    });

    observer.observe(element);

    return () => observer.disconnect();
  }, [hasBeenVisible, options]);

  return { elementRef, isVisible, hasBeenVisible };
};

// Hook for debounced values
export const useDebounce = <T>(value: T, delay: number): T => {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
};

// Hook for throttled callbacks
export const useThrottle = (callback: Function, delay: number) => {
  const lastRan = useRef(Date.now());

  return useCallback((...args: any[]) => {
    if (Date.now() - lastRan.current >= delay) {
      callback(...args);
      lastRan.current = Date.now();
    }
  }, [callback, delay]);
};

// Hook for media queries
export const useMediaQuery = (query: string): boolean => {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    const media = window.matchMedia(query);
    if (media.matches !== matches) {
      setMatches(media.matches);
    }

    const listener = (e: MediaQueryListEvent) => setMatches(e.matches);
    media.addEventListener('change', listener);
    
    return () => media.removeEventListener('change', listener);
  }, [matches, query]);

  return matches;
};

// Hook for localStorage with performance optimization
export const useLocalStorage = <T>(
  key: string, 
  initialValue: T
): [T, (value: T | ((val: T) => T)) => void] => {
  // State to store our value
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      console.error(`Error reading localStorage key "${key}":`, error);
      return initialValue;
    }
  });

  // Return a wrapped version of useState's setter function that persists the new value to localStorage
  const setValue = useCallback((value: T | ((val: T) => T)) => {
    try {
      // Allow value to be a function so we have the same API as useState
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      setStoredValue(valueToStore);
      
      // Save to local storage (debounced to prevent excessive writes)
      window.localStorage.setItem(key, JSON.stringify(valueToStore));
    } catch (error) {
      console.error(`Error setting localStorage key "${key}":`, error);
    }
  }, [key, storedValue]);

  return [storedValue, setValue];
};

// Hook for performance monitoring
export const usePerformance = (name: string) => {
  const startTimeRef = useRef<number>();

  const start = useCallback(() => {
    startTimeRef.current = performance.now();
  }, []);

  const end = useCallback(() => {
    if (startTimeRef.current) {
      const duration = performance.now() - startTimeRef.current;
      console.log(`Performance [${name}]: ${duration.toFixed(2)}ms`);
      
      // Send to analytics in production
      if (import.meta.env.PROD) {
        // Analytics code would go here
        // analytics.track('performance', { name, duration });
      }
    }
  }, [name]);

  return { start, end };
};

// Hook for lazy loading images
export const useLazyImage = (src: string, placeholder?: string) => {
  const [imageSrc, setImageSrc] = useState(placeholder || '');
  const [imageRef, setImageRef] = useState<HTMLImageElement | null>(null);
  const [isLoaded, setIsLoaded] = useState(false);
  const [hasError, setHasError] = useState(false);

  useEffect(() => {
    let observer: IntersectionObserver;

    if (imageRef) {
      observer = new IntersectionObserver(
        ([entry]) => {
          if (entry.isIntersecting) {
            setImageSrc(src);
            observer.unobserve(imageRef);
          }
        },
        { threshold: 0.1, rootMargin: '50px' }
      );

      observer.observe(imageRef);
    }

    return () => {
      if (observer && imageRef) {
        observer.unobserve(imageRef);
      }
    };
  }, [imageRef, src]);

  const handleLoad = useCallback(() => {
    setIsLoaded(true);
  }, []);

  const handleError = useCallback(() => {
    setHasError(true);
  }, []);

  return {
    src: imageSrc,
    setRef: setImageRef,
    isLoaded,
    hasError,
    onLoad: handleLoad,
    onError: handleError
  };
};

// Hook for resource cleanup
export const useCleanup = (cleanup: () => void) => {
  useEffect(() => {
    return cleanup;
  }, [cleanup]);
};

// Hook for scroll position optimization
export const useScrollPosition = () => {
  const [scrollPosition, setScrollPosition] = useState({
    x: 0,
    y: 0
  });

  const updatePosition = useThrottle(() => {
    setScrollPosition({
      x: window.pageXOffset,
      y: window.pageYOffset
    });
  }, 100); // Throttle to every 100ms

  useEffect(() => {
    window.addEventListener('scroll', updatePosition);
    return () => window.removeEventListener('scroll', updatePosition);
  }, [updatePosition]);

  return scrollPosition;
};

// Hook for window size optimization
export const useWindowSize = () => {
  const [windowSize, setWindowSize] = useState({
    width: typeof window !== 'undefined' ? window.innerWidth : 0,
    height: typeof window !== 'undefined' ? window.innerHeight : 0
  });

  const updateSize = useThrottle(() => {
    setWindowSize({
      width: window.innerWidth,
      height: window.innerHeight
    });
  }, 200); // Throttle to every 200ms

  useEffect(() => {
    window.addEventListener('resize', updateSize);
    return () => window.removeEventListener('resize', updateSize);
  }, [updateSize]);

  return windowSize;
};