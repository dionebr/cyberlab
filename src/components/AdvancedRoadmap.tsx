import React, { useState, useEffect } from 'react';
import { 
  Play, 
  CheckCircle, 
  Lock, 
  Star, 
  Target, 
  Zap,
  Trophy,
  Book,
  Code,
  Terminal,
  Brain,
  ArrowRight,
  Crown,
  Medal,
  Clock
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { cn } from '@/lib/utils';

interface RoadmapNode {
  id: string;
  title: string;
  description: string;
  type: 'lesson' | 'milestone' | 'skill-gate' | 'boss-challenge';
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  estimatedTime: number;
  points: number;
  prerequisites: string[];
  connections: string[]; // nodes this unlocks
  position: { x: number; y: number };
  status: 'locked' | 'available' | 'in-progress' | 'completed';
  category: 'web-security' | 'network-security' | 'os-security' | 'programming-security';
  badge?: string;
}

interface SkillTree {
  nodes: RoadmapNode[];
  paths: Array<{
    from: string;
    to: string;
    type: 'prerequisite' | 'recommended' | 'alternative';
  }>;
}

interface AdvancedRoadmapProps {
  skillTree: SkillTree;
  userProgress: Record<string, any>;
  onNodeSelect: (nodeId: string) => void;
  onStartNode: (nodeId: string) => void;
}

export const AdvancedRoadmap: React.FC<AdvancedRoadmapProps> = ({
  skillTree,
  userProgress,
  onNodeSelect,
  onStartNode
}) => {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'tree' | 'linear'>('tree');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [animatedPaths, setAnimatedPaths] = useState<Set<string>>(new Set());

  const getNodeIcon = (node: RoadmapNode) => {
    switch (node.type) {
      case 'milestone':
        return <Trophy className="w-5 h-5" />;
      case 'skill-gate':
        return <Crown className="w-5 h-5" />;
      case 'boss-challenge':
        return <Target className="w-5 h-5" />;
      default:
        return <Book className="w-4 h-4" />;
    }
  };

  const getNodeColor = (node: RoadmapNode) => {
    const baseColors = {
      'web-security': 'blue',
      'network-security': 'green', 
      'os-security': 'purple',
      'programming-security': 'orange'
    };

    const base = baseColors[node.category] || 'gray';
    
    switch (node.status) {
      case 'completed':
        return `bg-${base}-100 border-${base}-500 text-${base}-800`;
      case 'in-progress':
        return `bg-${base}-50 border-${base}-400 text-${base}-700 animate-pulse`;
      case 'available':
        return `bg-white border-${base}-300 text-${base}-600 hover:border-${base}-400 cursor-pointer`;
      case 'locked':
      default:
        return 'bg-gray-100 border-gray-300 text-gray-500';
    }
  };

  const getNodeSize = (node: RoadmapNode) => {
    switch (node.type) {
      case 'milestone':
        return 'w-20 h-20';
      case 'skill-gate':
        return 'w-18 h-18';
      case 'boss-challenge':
        return 'w-16 h-16';
      default:
        return 'w-14 h-14';
    }
  };

  const handleNodeClick = (node: RoadmapNode) => {
    if (node.status === 'locked') return;
    
    setSelectedNode(node.id);
    onNodeSelect(node.id);
    
    if (node.status === 'available') {
      // Animate connected paths
      const connectedPaths = skillTree.paths.filter(
        path => path.from === node.id || path.to === node.id
      );
      
      connectedPaths.forEach(path => {
        const pathId = `${path.from}-${path.to}`;
        setAnimatedPaths(prev => new Set([...prev, pathId]));
        setTimeout(() => {
          setAnimatedPaths(prev => {
            const newSet = new Set(prev);
            newSet.delete(pathId);
            return newSet;
          });
        }, 2000);
      });
    }
  };

  const renderTreeView = () => {
    const svgWidth = 1200;
    const svgHeight = 800;
    
    return (
      <div className="relative w-full h-[800px] overflow-auto bg-gradient-to-br from-blue-50 to-purple-50 rounded-lg border">
        <svg width={svgWidth} height={svgHeight} className="absolute inset-0">
          <defs>
            <pattern id="grid" width="50" height="50" patternUnits="userSpaceOnUse">
              <path d="M 50 0 L 0 0 0 50" fill="none" stroke="#e5e7eb" strokeWidth="1" opacity="0.3"/>
            </pattern>
            
            {/* Glow effects */}
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
              <feMerge> 
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>
          
          <rect width="100%" height="100%" fill="url(#grid)" />
          
          {/* Connection paths */}
          {skillTree.paths.map((path) => {
            const fromNode = skillTree.nodes.find(n => n.id === path.from);
            const toNode = skillTree.nodes.find(n => n.id === path.to);
            
            if (!fromNode || !toNode) return null;
            
            const pathId = `${path.from}-${path.to}`;
            const isAnimated = animatedPaths.has(pathId);
            
            // Calculate path with curves
            const x1 = fromNode.position.x + 30;
            const y1 = fromNode.position.y + 30;
            const x2 = toNode.position.x + 30;
            const y2 = toNode.position.y + 30;
            
            const midX = (x1 + x2) / 2;
            const midY = (y1 + y2) / 2;
            const offset = 20;
            
            const pathData = `M ${x1} ${y1} Q ${midX} ${midY - offset} ${x2} ${y2}`;
            
            return (
              <g key={pathId}>
                <path
                  d={pathData}
                  stroke={path.type === 'prerequisite' ? '#3b82f6' : 
                         path.type === 'recommended' ? '#10b981' : '#6b7280'}
                  strokeWidth={path.type === 'prerequisite' ? '3' : '2'}
                  fill="none"
                  strokeDasharray={path.type === 'recommended' ? '5,5' : 
                                 path.type === 'alternative' ? '10,5' : 'none'}
                  opacity={fromNode.status === 'completed' ? 1 : 0.3}
                  className={isAnimated ? 'animate-pulse' : ''}
                />
                
                {/* Arrow marker */}
                <circle
                  cx={midX}
                  cy={midY - offset}
                  r="3"
                  fill={path.type === 'prerequisite' ? '#3b82f6' : 
                        path.type === 'recommended' ? '#10b981' : '#6b7280'}
                  opacity={fromNode.status === 'completed' ? 1 : 0.3}
                />
              </g>
            );
          })}
          
          {/* Nodes */}
          {skillTree.nodes.map((node) => {
            const isSelected = selectedNode === node.id;
            const isHovered = hoveredNode === node.id;
            
            return (
              <g key={node.id}>
                {/* Selection glow */}
                {(isSelected || isHovered) && (
                  <circle
                    cx={node.position.x + 30}
                    cy={node.position.y + 30}
                    r="35"
                    fill="none"
                    stroke="#3b82f6"
                    strokeWidth="2"
                    opacity="0.6"
                    filter="url(#glow)"
                    className="animate-pulse"
                  />
                )}
              </g>
            );
          })}
        </svg>
        
        {/* Node components */}
        {skillTree.nodes.map((node) => (
          <div
            key={node.id}
            className={cn(
              "absolute transform -translate-x-1/2 -translate-y-1/2",
              "transition-all duration-200 hover:scale-110",
              getNodeSize(node)
            )}
            style={{
              left: node.position.x + 30,
              top: node.position.y + 30
            }}
            onClick={() => handleNodeClick(node)}
            onMouseEnter={() => setHoveredNode(node.id)}
            onMouseLeave={() => setHoveredNode(null)}
          >
            <Card className={cn(
              "w-full h-full border-2 shadow-lg transition-all duration-200",
              getNodeColor(node),
              selectedNode === node.id && "ring-2 ring-blue-400",
              node.status === 'locked' && "cursor-not-allowed"
            )}>
              <CardContent className="p-2 h-full flex flex-col items-center justify-center text-center">
                <div className="mb-1">
                  {getNodeIcon(node)}
                </div>
                
                <div className="text-xs font-semibold line-clamp-2">
                  {node.title}
                </div>
                
                {/* Status indicators */}
                <div className="flex gap-1 mt-1">
                  {node.status === 'completed' && (
                    <CheckCircle className="w-3 h-3 text-green-600" />
                  )}
                  {node.status === 'in-progress' && (
                    <Play className="w-3 h-3 text-blue-600" />
                  )}
                  {node.status === 'locked' && (
                    <Lock className="w-3 h-3 text-gray-400" />
                  )}
                </div>
                
                {/* Points badge for larger nodes */}
                {node.type !== 'lesson' && (
                  <Badge variant="secondary" className="text-xs mt-1">
                    {node.points}pts
                  </Badge>
                )}
              </CardContent>
            </Card>
          </div>
        ))}
        
        {/* Legend */}
        <div className="absolute bottom-4 left-4 bg-white/90 backdrop-blur-sm p-4 rounded-lg shadow-lg">
          <h4 className="font-semibold text-sm mb-2">Legenda</h4>
          <div className="space-y-1 text-xs">
            <div className="flex items-center gap-2">
              <div className="w-3 h-0.5 bg-blue-500"></div>
              <span>Pré-requisito</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-0.5 bg-green-500 border-dashed"></div>
              <span>Recomendado</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-0.5 bg-gray-500 border-dotted"></div>
              <span>Alternativo</span>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderLinearView = () => {
    const categories = ['web-security', 'network-security', 'os-security', 'programming-security'];
    
    return (
      <div className="space-y-8">
        {categories.map(category => {
          const categoryNodes = skillTree.nodes.filter(node => 
            node.category === category && 
            (filterCategory === 'all' || filterCategory === category)
          );
          
          if (categoryNodes.length === 0) return null;
          
          return (
            <div key={category} className="space-y-4">
              <div className="flex items-center gap-3">
                <h3 className="text-lg font-semibold capitalize">
                  {category.replace('-', ' ')}
                </h3>
                <Badge variant="outline">
                  {categoryNodes.length} lições
                </Badge>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {categoryNodes.map(node => (
                  <Card
                    key={node.id}
                    className={cn(
                      "cursor-pointer transition-all duration-200 hover:shadow-lg",
                      getNodeColor(node),
                      selectedNode === node.id && "ring-2 ring-blue-400",
                      node.status === 'locked' && "cursor-not-allowed opacity-60"
                    )}
                    onClick={() => handleNodeClick(node)}
                  >
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-2">
                          {getNodeIcon(node)}
                          <Badge variant="outline" className="text-xs">
                            {node.difficulty}
                          </Badge>
                        </div>
                        
                        <div className="flex items-center gap-1">
                          {node.status === 'completed' && (
                            <CheckCircle className="w-4 h-4 text-green-600" />
                          )}
                          {node.status === 'in-progress' && (
                            <Play className="w-4 h-4 text-blue-600" />
                          )}
                          {node.status === 'locked' && (
                            <Lock className="w-4 h-4 text-gray-400" />
                          )}
                        </div>
                      </div>
                      
                      <h4 className="font-semibold text-sm mb-2">{node.title}</h4>
                      <p className="text-xs text-muted-foreground line-clamp-2 mb-3">
                        {node.description}
                      </p>
                      
                      <div className="flex items-center justify-between text-xs">
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {node.estimatedTime}min
                        </span>
                        <span className="flex items-center gap-1">
                          <Star className="w-3 h-3" />
                          {node.points}pts
                        </span>
                      </div>
                      
                      {node.status === 'available' && (
                        <Button 
                          size="sm" 
                          className="w-full mt-3"
                          onClick={(e) => {
                            e.stopPropagation();
                            onStartNode(node.id);
                          }}
                        >
                          Iniciar
                        </Button>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="w-full space-y-6">
      {/* Controls */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex gap-2">
          <Button
            variant={viewMode === 'tree' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setViewMode('tree')}
          >
            Árvore de Skills
          </Button>
          <Button
            variant={viewMode === 'linear' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setViewMode('linear')}
          >
            Visualização Linear
          </Button>
        </div>
        
        {viewMode === 'linear' && (
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="px-3 py-1 border rounded text-sm"
          >
            <option value="all">Todas as categorias</option>
            <option value="web-security">Web Security</option>
            <option value="network-security">Network Security</option>
            <option value="os-security">OS Security</option>
            <option value="programming-security">Programming Security</option>
          </select>
        )}
      </div>

      {/* Progress Overview */}
      <Card>
        <CardContent className="p-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">
                {skillTree.nodes.filter(n => n.status === 'completed').length}
              </div>
              <div className="text-xs text-muted-foreground">Concluídas</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {skillTree.nodes.filter(n => n.status === 'available').length}
              </div>
              <div className="text-xs text-muted-foreground">Disponíveis</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-600">
                {skillTree.nodes.filter(n => n.status === 'in-progress').length}
              </div>
              <div className="text-xs text-muted-foreground">Em Progresso</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-600">
                {skillTree.nodes.filter(n => n.status === 'locked').length}
              </div>
              <div className="text-xs text-muted-foreground">Bloqueadas</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Main content */}
      {viewMode === 'tree' ? renderTreeView() : renderLinearView()}

      {/* Selected node details */}
      {selectedNode && (
        <Card className="border-blue-200 bg-blue-50">
          <CardContent className="p-4">
            {(() => {
              const node = skillTree.nodes.find(n => n.id === selectedNode);
              if (!node) return null;
              
              return (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="font-semibold flex items-center gap-2">
                      {getNodeIcon(node)}
                      {node.title}
                    </h4>
                    <Badge variant="outline">{node.category}</Badge>
                  </div>
                  
                  <p className="text-sm text-muted-foreground">
                    {node.description}
                  </p>
                  
                  <div className="flex items-center gap-4 text-sm">
                    <span>⏱️ {node.estimatedTime} min</span>
                    <span>⭐ {node.points} pontos</span>
                    <span>📚 {node.difficulty}</span>
                  </div>
                  
                  {node.prerequisites.length > 0 && (
                    <div className="text-sm">
                      <strong>Pré-requisitos:</strong>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {node.prerequisites.map(prereq => {
                          const prereqNode = skillTree.nodes.find(n => n.id === prereq);
                          return (
                            <Badge key={prereq} variant="secondary" className="text-xs">
                              {prereqNode?.title || prereq}
                            </Badge>
                          );
                        })}
                      </div>
                    </div>
                  )}
                  
                  {node.status === 'available' && (
                    <Button 
                      className="gap-2" 
                      onClick={() => onStartNode(node.id)}
                    >
                      <Play className="w-4 h-4" />
                      Iniciar {node.title}
                    </Button>
                  )}
                </div>
              );
            })()}
          </CardContent>
        </Card>
      )}
    </div>
  );
};