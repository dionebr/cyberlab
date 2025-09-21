import React, { useState, useEffect } from 'react';
import { 
  ExternalLink, 
  BookOpen, 
  Video, 
  Award, 
  Users,
  Star,
  Clock,
  TrendingUp,
  Filter,
  Search,
  Globe,
  Bookmark,
  BookmarkCheck
} from 'lucide-react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';

export interface ExternalResource {
  id: string;
  title: string;
  description: string;
  type: 'course' | 'certification' | 'book' | 'video' | 'article' | 'tool' | 'lab';
  provider: string;
  url: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  duration?: string; // e.g., "4 hours", "3 weeks", "Self-paced"
  price: 'free' | 'paid' | 'freemium';
  rating: number; // 1-5
  tags: string[];
  prerequisites?: string[];
  relevantSkills: string[];
  estimatedTime?: number; // in hours
  language: string;
  lastUpdated: Date;
  popularity: number; // 1-100
  certified?: boolean;
  thumbnail?: string;
}

interface SmartSuggestionsProps {
  userProgress: {
    completedLessons: string[];
    currentSkills: string[];
    weakAreas: string[];
    interests: string[];
    level: 'beginner' | 'intermediate' | 'advanced';
  };
  resources: ExternalResource[];
  savedResources: string[];
  onSaveResource: (resourceId: string) => void;
  onUnsaveResource: (resourceId: string) => void;
}

export const SmartSuggestions: React.FC<SmartSuggestionsProps> = ({
  userProgress,
  resources,
  savedResources,
  onSaveResource,
  onUnsaveResource
}) => {
  const [filteredResources, setFilteredResources] = useState<ExternalResource[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [difficultyFilter, setDifficultyFilter] = useState<string>('all');
  const [priceFilter, setPriceFilter] = useState<string>('all');
  const [activeTab, setActiveTab] = useState('personalized');

  // Smart recommendation algorithm
  const getPersonalizedScore = (resource: ExternalResource): number => {
    let score = 0;

    // Skill relevance (40% weight)
    const skillMatch = resource.relevantSkills.filter(skill =>
      userProgress.currentSkills.includes(skill) || 
      userProgress.interests.includes(skill)
    ).length;
    score += (skillMatch / Math.max(resource.relevantSkills.length, 1)) * 40;

    // Weak areas bonus (30% weight)
    const weakAreaMatch = resource.relevantSkills.filter(skill =>
      userProgress.weakAreas.includes(skill)
    ).length;
    score += (weakAreaMatch / Math.max(userProgress.weakAreas.length, 1)) * 30;

    // Level appropriateness (15% weight)
    if (resource.difficulty === userProgress.level) {
      score += 15;
    } else if (
      (userProgress.level === 'intermediate' && resource.difficulty === 'beginner') ||
      (userProgress.level === 'advanced' && ['beginner', 'intermediate'].includes(resource.difficulty))
    ) {
      score += 10; // Some bonus for foundational content
    }

    // Quality indicators (10% weight)
    score += (resource.rating / 5) * 5; // Rating contribution
    score += (resource.popularity / 100) * 5; // Popularity contribution

    // Recent updates bonus (5% weight)
    const monthsOld = (Date.now() - resource.lastUpdated.getTime()) / (1000 * 60 * 60 * 24 * 30);
    if (monthsOld < 6) score += 5;
    else if (monthsOld < 12) score += 3;

    return Math.min(100, score);
  };

  // Filter and sort resources
  useEffect(() => {
    let filtered = resources;

    // Apply filters
    if (searchTerm) {
      filtered = filtered.filter(resource =>
        resource.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        resource.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        resource.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    }

    if (typeFilter !== 'all') {
      filtered = filtered.filter(resource => resource.type === typeFilter);
    }

    if (difficultyFilter !== 'all') {
      filtered = filtered.filter(resource => resource.difficulty === difficultyFilter);
    }

    if (priceFilter !== 'all') {
      filtered = filtered.filter(resource => resource.price === priceFilter);
    }

    // Sort by personalized score for personalized tab
    if (activeTab === 'personalized') {
      filtered = filtered
        .map(resource => ({
          ...resource,
          personalizedScore: getPersonalizedScore(resource)
        }))
        .sort((a, b) => (b as any).personalizedScore - (a as any).personalizedScore)
        .slice(0, 20); // Show top 20 recommendations
    } else if (activeTab === 'trending') {
      filtered = filtered
        .sort((a, b) => b.popularity - a.popularity)
        .slice(0, 20);
    } else if (activeTab === 'saved') {
      filtered = filtered.filter(resource => savedResources.includes(resource.id));
    }

    setFilteredResources(filtered);
  }, [resources, searchTerm, typeFilter, difficultyFilter, priceFilter, activeTab, userProgress, savedResources]);

  const getResourceIcon = (type: string) => {
    switch (type) {
      case 'course':
        return <BookOpen className="w-4 h-4" />;
      case 'certification':
        return <Award className="w-4 h-4" />;
      case 'video':
        return <Video className="w-4 h-4" />;
      case 'book':
        return <BookOpen className="w-4 h-4" />;
      case 'tool':
        return <Globe className="w-4 h-4" />;
      default:
        return <ExternalLink className="w-4 h-4" />;
    }
  };

  const getResourceColor = (type: string) => {
    const colors = {
      course: 'bg-blue-100 text-blue-800',
      certification: 'bg-purple-100 text-purple-800',
      video: 'bg-red-100 text-red-800',
      book: 'bg-green-100 text-green-800',
      article: 'bg-yellow-100 text-yellow-800',
      tool: 'bg-gray-100 text-gray-800',
      lab: 'bg-orange-100 text-orange-800'
    };
    return colors[type as keyof typeof colors] || 'bg-gray-100 text-gray-800';
  };

  const getDifficultyColor = (difficulty: string) => {
    const colors = {
      beginner: 'text-green-600',
      intermediate: 'text-yellow-600',
      advanced: 'text-red-600'
    };
    return colors[difficulty as keyof typeof colors] || 'text-gray-600';
  };

  const renderResourceCard = (resource: ExternalResource, showScore = false) => {
    const isSaved = savedResources.includes(resource.id);
    const personalizedScore = showScore ? getPersonalizedScore(resource) : 0;

    return (
      <Card key={resource.id} className="group hover:shadow-lg transition-all duration-200">
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-2">
                <Badge className={getResourceColor(resource.type)}>
                  {getResourceIcon(resource.type)}
                  <span className="ml-1 capitalize">{resource.type}</span>
                </Badge>
                {resource.certified && (
                  <Badge variant="secondary" className="text-xs">
                    <Award className="w-3 h-3 mr-1" />
                    Certificado
                  </Badge>
                )}
                {showScore && personalizedScore > 70 && (
                  <Badge variant="default" className="bg-green-600 text-xs">
                    {Math.round(personalizedScore)}% match
                  </Badge>
                )}
              </div>
              
              <h3 className="font-semibold text-sm mb-1 line-clamp-2 group-hover:text-blue-600 transition-colors">
                {resource.title}
              </h3>
              
              <p className="text-xs text-muted-foreground mb-2">
                por {resource.provider}
              </p>
            </div>
            
            <Button
              variant="ghost"
              size="sm"
              onClick={() => isSaved ? onUnsaveResource(resource.id) : onSaveResource(resource.id)}
              className="p-1"
            >
              {isSaved ? (
                <BookmarkCheck className="w-4 h-4 text-blue-600" />
              ) : (
                <Bookmark className="w-4 h-4" />
              )}
            </Button>
          </div>
        </CardHeader>
        
        <CardContent className="space-y-3">
          <p className="text-sm line-clamp-2">{resource.description}</p>
          
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <Star className="w-3 h-3 fill-current text-yellow-500" />
              {resource.rating.toFixed(1)}
            </div>
            
            <div className={`font-medium ${getDifficultyColor(resource.difficulty)}`}>
              {resource.difficulty}
            </div>
            
            {resource.duration && (
              <div className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {resource.duration}
              </div>
            )}
            
            <Badge 
              variant={resource.price === 'free' ? 'secondary' : 'outline'}
              className="text-xs"
            >
              {resource.price === 'free' ? 'Grátis' : 
               resource.price === 'paid' ? 'Pago' : 'Freemium'}
            </Badge>
          </div>
          
          <div className="flex flex-wrap gap-1">
            {resource.tags.slice(0, 4).map(tag => (
              <Badge key={tag} variant="outline" className="text-xs">
                {tag}
              </Badge>
            ))}
            {resource.tags.length > 4 && (
              <Badge variant="outline" className="text-xs">
                +{resource.tags.length - 4}
              </Badge>
            )}
          </div>
          
          <div className="flex gap-2 pt-2">
            <Button 
              size="sm" 
              className="flex-1 text-xs" 
              onClick={() => window.open(resource.url, '_blank')}
            >
              <ExternalLink className="w-3 h-3 mr-1" />
              Acessar
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  };

  const getPersonalizedMessage = () => {
    const weakAreasText = userProgress.weakAreas.length > 0 
      ? `Detectamos que você pode melhorar em: ${userProgress.weakAreas.slice(0, 2).join(', ')}. `
      : '';
    
    const levelText = `Como você está no nível ${userProgress.level}, `;
    
    return `${levelText}${weakAreasText}Aqui estão recursos personalizados para acelerar seu aprendizado!`;
  };

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6">
      {/* Search and Filters */}
      <div className="space-y-4">
        <div className="flex gap-4">
          <div className="flex-1">
            <Input
              placeholder="Search courses, certifications, tools..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full"
            />
          </div>
          <Button variant="outline" size="sm">
            <Filter className="w-4 h-4" />
          </Button>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-1 border rounded text-sm"
          >
            <option value="all">Todos os tipos</option>
            <option value="course">Cursos</option>
            <option value="certification">Certifications</option>
            <option value="video">Vídeos</option>
            <option value="book">Livros</option>
            <option value="article">Artigos</option>
            <option value="tool">Ferramentas</option>
            <option value="lab">Labs</option>
          </select>
          
          <select
            value={difficultyFilter}
            onChange={(e) => setDifficultyFilter(e.target.value)}
            className="px-3 py-1 border rounded text-sm"
          >
            <option value="all">Qualquer nível</option>
            <option value="beginner">Iniciante</option>
            <option value="intermediate">Intermediate</option>
            <option value="advanced">Avançado</option>
          </select>
          
          <select
            value={priceFilter}
            onChange={(e) => setPriceFilter(e.target.value)}
            className="px-3 py-1 border rounded text-sm"
          >
            <option value="all">Qualquer preço</option>
            <option value="free">Grátis</option>
            <option value="freemium">Freemium</option>
            <option value="paid">Pagos</option>
          </select>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="personalized" className="gap-2">
            <TrendingUp className="w-4 h-4" />
            Para Você
          </TabsTrigger>
          <TabsTrigger value="trending" className="gap-2">
            <Star className="w-4 h-4" />
            Em Alta
          </TabsTrigger>
          <TabsTrigger value="saved" className="gap-2">
            <Bookmark className="w-4 h-4" />
            Salvos ({savedResources.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="personalized" className="space-y-4">
          <Alert>
            <TrendingUp className="h-4 w-4" />
            <AlertDescription>
              {getPersonalizedMessage()}
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredResources.map(resource => renderResourceCard(resource, true))}
          </div>
        </TabsContent>

        <TabsContent value="trending" className="space-y-4">
          <Alert>
            <Star className="h-4 w-4" />
            <AlertDescription>
              Os recursos mais populares e bem avaliados pela comunidade de cybersecurity.
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredResources.map(resource => renderResourceCard(resource))}
          </div>
        </TabsContent>

        <TabsContent value="saved" className="space-y-4">
          {filteredResources.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredResources.map(resource => renderResourceCard(resource))}
            </div>
          ) : (
            <div className="text-center py-12">
              <Bookmark className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
              <h3 className="text-lg font-semibold mb-2">Nenhum recurso salvo</h3>
              <p className="text-muted-foreground">
                Explore the "For You" and "Trending" tabs to discover interesting content.
              </p>
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Stats */}
      <Card>
        <CardContent className="p-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
            <div>
              <div className="text-2xl font-bold text-blue-600">
                {resources.filter(r => r.price === 'free').length}
              </div>
              <div className="text-xs text-muted-foreground">Recursos Gratuitos</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-green-600">
                {resources.filter(r => r.type === 'certification').length}
              </div>
              <div className="text-xs text-muted-foreground">Certifications</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-purple-600">
                {resources.filter(r => r.rating >= 4.5).length}
              </div>
              <div className="text-xs text-muted-foreground">Alta Qualidade</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-orange-600">
                {savedResources.length}
              </div>
              <div className="text-xs text-muted-foreground">Salvos por Você</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};