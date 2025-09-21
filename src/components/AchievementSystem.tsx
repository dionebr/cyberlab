import React, { useState, useEffect } from 'react';
import { Trophy, Star, Zap, Award, Target, Crown, Medal, Sparkles, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

export interface Achievement {
  id: string;
  title: string;
  description: string;
  icon: string;
  points: number;
  rarity: 'common' | 'rare' | 'epic' | 'legendary';
  category: 'progress' | 'skill' | 'speed' | 'exploration' | 'mastery';
  unlockedAt?: Date;
}

export interface Notification {
  id: string;
  type: 'achievement' | 'points' | 'level-up' | 'streak' | 'completion';
  title: string;
  message: string;
  icon?: React.ReactNode;
  points?: number;
  achievement?: Achievement;
  timestamp: Date;
  duration?: number; // in milliseconds
}

interface AchievementSystemProps {
  notifications: Notification[];
  onDismissNotification: (id: string) => void;
  achievements: Achievement[];
  userLevel: number;
  userPoints: number;
}

export const AchievementSystem: React.FC<AchievementSystemProps> = ({
  notifications,
  onDismissNotification,
  achievements,
  userLevel,
  userPoints
}) => {
  const [visibleNotifications, setVisibleNotifications] = useState<Notification[]>([]);

  useEffect(() => {
    if (notifications.length > 0) {
      const newNotification = notifications[notifications.length - 1];
      setVisibleNotifications(prev => [...prev, newNotification]);

      // Auto dismiss after duration
      const timeout = setTimeout(() => {
        setVisibleNotifications(prev => prev.filter(n => n.id !== newNotification.id));
        onDismissNotification(newNotification.id);
      }, newNotification.duration || 5000);

      return () => clearTimeout(timeout);
    }
  }, [notifications, onDismissNotification]);

  const getRarityColor = (rarity: string) => {
    const colors = {
      common: 'from-gray-400 to-gray-600',
      rare: 'from-blue-400 to-blue-600',
      epic: 'from-purple-400 to-purple-600',
      legendary: 'from-yellow-400 to-yellow-600'
    };
    return colors[rarity as keyof typeof colors] || colors.common;
  };

  const getRarityGlow = (rarity: string) => {
    const glows = {
      common: 'shadow-gray-400/20',
      rare: 'shadow-blue-400/30',
      epic: 'shadow-purple-400/40',
      legendary: 'shadow-yellow-400/50'
    };
    return glows[rarity as keyof typeof glows] || glows.common;
  };

  const getNotificationIcon = (notification: Notification) => {
    if (notification.icon) return notification.icon;
    
    switch (notification.type) {
      case 'achievement':
        return <Trophy className="w-6 h-6" />;
      case 'points':
        return <Star className="w-6 h-6" />;
      case 'level-up':
        return <Crown className="w-6 h-6" />;
      case 'streak':
        return <Zap className="w-6 h-6" />;
      case 'completion':
        return <Target className="w-6 h-6" />;
      default:
        return <Sparkles className="w-6 h-6" />;
    }
  };

  const dismissNotification = (id: string) => {
    setVisibleNotifications(prev => prev.filter(n => n.id !== id));
    onDismissNotification(id);
  };

  return (
    <div className="fixed top-4 right-4 z-50 space-y-2 max-w-sm">
      {visibleNotifications.map((notification, index) => (
        <div
          key={notification.id}
          className={cn(
            "transform transition-all duration-300 ease-in-out",
            "animate-in slide-in-from-right-full",
            index > 0 && "mt-2"
          )}
          style={{
            animationDelay: `${index * 100}ms`,
            animationDuration: '300ms'
          }}
        >
          {notification.type === 'achievement' && notification.achievement && (
            <AchievementCard
              achievement={notification.achievement}
              onDismiss={() => dismissNotification(notification.id)}
            />
          )}
          
          {notification.type === 'level-up' && (
            <LevelUpCard
              level={userLevel}
              points={userPoints}
              onDismiss={() => dismissNotification(notification.id)}
            />
          )}
          
          {(['points', 'streak', 'completion'].includes(notification.type)) && (
            <SimpleNotificationCard
              notification={notification}
              onDismiss={() => dismissNotification(notification.id)}
            />
          )}
        </div>
      ))}
    </div>
  );
};

interface AchievementCardProps {
  achievement: Achievement;
  onDismiss: () => void;
}

const AchievementCard: React.FC<AchievementCardProps> = ({ achievement, onDismiss }) => {
  const getRarityColor = (rarity: string) => {
    const colors = {
      common: 'from-gray-400 to-gray-600',
      rare: 'from-blue-400 to-blue-600',
      epic: 'from-purple-400 to-purple-600',
      legendary: 'from-yellow-400 to-yellow-600'
    };
    return colors[rarity as keyof typeof colors] || colors.common;
  };

  const getRarityGlow = (rarity: string) => {
    const glows = {
      common: 'shadow-gray-400/20',
      rare: 'shadow-blue-400/30',
      epic: 'shadow-purple-400/40',
      legendary: 'shadow-yellow-400/50'
    };
    return glows[rarity as keyof typeof glows] || glows.common;
  };

  return (
    <Card className={cn(
      "relative overflow-hidden border-2 shadow-lg",
      `bg-gradient-to-r ${getRarityColor(achievement.rarity)}`,
      `shadow-xl ${getRarityGlow(achievement.rarity)}`,
      "animate-pulse-slow"
    )}>
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent opacity-30 animate-shimmer" />
      
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="text-4xl animate-bounce">
              {achievement.icon}
            </div>
            <div>
              <h3 className="font-bold text-white text-lg">
                🏆 Conquista Desbloqueada!
              </h3>
              <p className="font-semibold text-white/90">{achievement.title}</p>
              <p className="text-white/80 text-sm">{achievement.description}</p>
              <div className="flex items-center gap-2 mt-2">
                <Badge variant="secondary" className="bg-white/20 text-white">
                  +{achievement.points} pontos
                </Badge>
                <Badge 
                  variant="outline" 
                  className={cn(
                    "border-white/40 text-white text-xs font-medium",
                    achievement.rarity === 'legendary' && "animate-pulse"
                  )}
                >
                  {achievement.rarity.toUpperCase()}
                </Badge>
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="ghost"
            onClick={onDismiss}
            className="text-white/80 hover:text-white hover:bg-white/20"
          >
            <X className="w-4 h-4" />
          </Button>
        </div>
      </CardContent>
      
      {/* Sparkle effects */}
      <div className="absolute top-2 left-2 text-white/40 animate-pulse">
        <Sparkles className="w-4 h-4" />
      </div>
      <div className="absolute bottom-2 right-2 text-white/40 animate-pulse" style={{animationDelay: '0.5s'}}>
        <Sparkles className="w-3 h-3" />
      </div>
      <div className="absolute top-1/2 right-8 text-white/30 animate-pulse" style={{animationDelay: '1s'}}>
        <Sparkles className="w-2 h-2" />
      </div>
    </Card>
  );
};

interface LevelUpCardProps {
  level: number;
  points: number;
  onDismiss: () => void;
}

const LevelUpCard: React.FC<LevelUpCardProps> = ({ level, points, onDismiss }) => {
  return (
    <Card className="relative overflow-hidden border-2 border-yellow-400 bg-gradient-to-r from-yellow-400 to-yellow-600 shadow-xl shadow-yellow-400/50">
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent opacity-50 animate-shimmer" />
      
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="text-5xl animate-bounce">
              👑
            </div>
            <div>
              <h3 className="font-bold text-white text-xl">
                LEVEL UP!
              </h3>
              <p className="font-semibold text-white/90 text-lg">Nível {level}</p>
              <p className="text-white/80">Você está dominando cybersecurity!</p>
              <div className="flex items-center gap-2 mt-2">
                <Badge variant="secondary" className="bg-white/20 text-white">
                  {points} pontos totais
                </Badge>
                <Badge variant="outline" className="border-white/40 text-white animate-pulse">
                  ÉPICO
                </Badge>
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="ghost"
            onClick={onDismiss}
            className="text-white/80 hover:text-white hover:bg-white/20"
          >
            <X className="w-4 h-4" />
          </Button>
        </div>
      </CardContent>
      
      {/* Crown sparkles */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-3 left-6 text-white/50 animate-ping">✨</div>
        <div className="absolute top-8 right-4 text-white/50 animate-ping" style={{animationDelay: '0.3s'}}>⭐</div>
        <div className="absolute bottom-4 left-4 text-white/50 animate-ping" style={{animationDelay: '0.6s'}}>💫</div>
        <div className="absolute bottom-6 right-8 text-white/50 animate-ping" style={{animationDelay: '0.9s'}}>✨</div>
      </div>
    </Card>
  );
};

interface SimpleNotificationCardProps {
  notification: Notification;
  onDismiss: () => void;
}

const SimpleNotificationCard: React.FC<SimpleNotificationCardProps> = ({ notification, onDismiss }) => {
  const getBackgroundColor = () => {
    switch (notification.type) {
      case 'points':
        return 'from-blue-500 to-blue-600';
      case 'streak':
        return 'from-orange-500 to-orange-600';
      case 'completion':
        return 'from-green-500 to-green-600';
      default:
        return 'from-gray-500 to-gray-600';
    }
  };

  const getNotificationIcon = (notification: Notification) => {
    if (notification.icon) return notification.icon;
    
    switch (notification.type) {
      case 'achievement':
        return <Trophy className="w-6 h-6" />;
      case 'points':
        return <Star className="w-6 h-6" />;
      case 'level-up':
        return <Crown className="w-6 h-6" />;
      case 'streak':
        return <Zap className="w-6 h-6" />;
      case 'completion':
        return <Target className="w-6 h-6" />;
      default:
        return <Sparkles className="w-6 h-6" />;
    }
  };

  return (
    <Card className={cn(
      "relative overflow-hidden border border-gray-200/50 shadow-lg",
      `bg-gradient-to-r ${getBackgroundColor()}`
    )}>
      <CardContent className="p-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="text-white text-lg animate-pulse">
              {getNotificationIcon(notification)}
            </div>
            <div>
              <p className="font-semibold text-white text-sm">{notification.title}</p>
              <p className="text-white/80 text-xs">{notification.message}</p>
              {notification.points && (
                <Badge variant="secondary" className="bg-white/20 text-white text-xs mt-1">
                  +{notification.points} pontos
                </Badge>
              )}
            </div>
          </div>
          <Button
            size="sm"
            variant="ghost"
            onClick={onDismiss}
            className="text-white/80 hover:text-white hover:bg-white/20 h-6 w-6 p-0"
          >
            <X className="w-3 h-3" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};