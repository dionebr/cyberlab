import { useState, useRef, useEffect, KeyboardEvent } from 'react';
import { X, MessageCircle, Send, RotateCcw, Copy, ThumbsUp, ThumbsDown } from 'lucide-react';
import { useChatBot } from '@/hooks/useChatBot';
import { cn } from '@/lib/utils';

interface FloatingChatProps {
  className?: string;
}

export const FloatingChat = ({ className }: FloatingChatProps) => {
  const {
    messages,
    isOpen,
    isLoading,
    hasUnreadMessages,
    toggleChat,
    closeChat,
    processUserMessage,
    markMessageHelpful,
    clearHistory,
    exportPayloads
  } = useChatBot();

  const [inputValue, setInputValue] = useState('');
  const [forceRender, setForceRender] = useState(0);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Force re-render to ensure chat state updates
  useEffect(() => {
    const interval = setInterval(() => {
      setForceRender(prev => prev + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  // Focus input when chat opens
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  const handleSendMessage = async () => {
    if (!inputValue.trim() || isLoading) return;
    
    const message = inputValue.trim();
    setInputValue('');
    await processUserMessage(message);
  };

  const handleKeyPress = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const formatMessageContent = (content: string) => {
    return content.split('\n').map((line, index) => {
      // Handle code blocks
      if (line.includes('`')) {
        const parts = line.split('`');
        return (
          <div key={index} className="mb-1">
            {parts.map((part, i) => 
              i % 2 === 1 ? (
                <code key={i} className="bg-gray-700 text-green-400 px-1 py-0.5 rounded text-sm font-mono">
                  {part}
                </code>
              ) : (
                part
              )
            )}
          </div>
        );
      }
      
      // Handle bullet points
      if (line.startsWith('•') || line.match(/^\d+\./)) {
        return (
          <div key={index} className="ml-2 mb-1 text-gray-300">
            {line}
          </div>
        );
      }
      
      // Handle bold text
      if (line.includes('**')) {
        const parts = line.split('**');
        return (
          <div key={index} className="mb-1">
            {parts.map((part, i) => 
              i % 2 === 1 ? (
                <strong key={i} className="text-white font-semibold">
                  {part}
                </strong>
              ) : (
                part
              )
            )}
          </div>
        );
      }
      
      return line ? (
        <div key={index} className="mb-1">
          {line}
        </div>
      ) : (
        <div key={index} className="mb-2" />
      );
    });
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (error) {
      console.error('Failed to copy text:', error);
    }
  };

  return (
    <div className="floating-chat-container">
      {/* Chat Toggle Button */}
      <div 
        className={cn(
          "absolute bottom-6 right-6 transition-all duration-300 ease-in-out",
          isOpen ? "opacity-0 scale-0" : "opacity-100 scale-100"
        )}
      >
        <button
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            toggleChat();
          }}
          className={cn(
            "relative bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400",
            "text-white p-4 rounded-full shadow-2xl transform transition-all duration-300",
            "hover:scale-110 active:scale-95 group hover:animate-none",
            "border border-cyan-400/50"
          )}
        >
          <MessageCircle className="w-6 h-6" />
          
          {/* Floating rings animation */}
          <div className="absolute inset-0 rounded-full border-2 border-cyan-400/30 animate-ping" />
          <div className="absolute inset-0 rounded-full border border-cyan-400/50 animate-pulse" />
        </button>
      </div>

      {/* Chat Window */}
      <div 
        className={cn(
          "absolute bottom-6 right-6 w-96 h-[500px] bg-gray-900/95 backdrop-blur-lg",
          "rounded-2xl shadow-2xl border border-gray-700/50 transition-all duration-300 ease-in-out",
          isOpen ? "opacity-100 scale-100 translate-y-0" : "opacity-0 scale-95 translate-y-4 pointer-events-none"
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-700/50 bg-gradient-to-r from-gray-800/50 to-gray-700/50 rounded-t-2xl">
          <div className="flex items-center space-x-3">
            <div className="relative">
              <div className="w-8 h-8 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full flex items-center justify-center">
                <MessageCircle className="w-4 h-4 text-white" />
              </div>
              <div className="absolute -bottom-1 -right-1 w-3 h-3 bg-green-400 rounded-full border-2 border-gray-900 animate-pulse" />
            </div>
            <div>
              <h3 className="text-white font-semibold text-sm">Security Assistant</h3>
              <p className="text-gray-400 text-xs">Online • Ready to help</p>
            </div>
          </div>
          
          <div className="flex items-center space-x-2">
            <button
              onClick={clearHistory}
              className="text-gray-400 hover:text-white p-1.5 rounded-lg hover:bg-gray-700/50 transition-colors"
              title="Clear chat history"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
            <button
              onClick={closeChat}
              className="text-gray-400 hover:text-white p-1.5 rounded-lg hover:bg-gray-700/50 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 h-[360px] scrollbar-thin scrollbar-thumb-gray-600 scrollbar-track-transparent">
          {messages.map((message) => (
            <div
              key={message.id}
              className={cn(
                "flex",
                message.type === 'user' ? 'justify-end' : 'justify-start'
              )}
            >
              <div
                className={cn(
                  "max-w-[80%] rounded-2xl px-4 py-2 text-sm animate-in slide-in-from-bottom-2 duration-300",
                  message.type === 'user'
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white'
                    : 'bg-gray-800/80 text-gray-200 border border-gray-700/50'
                )}
              >
                <div className="break-words">
                  {typeof message.content === 'string' 
                    ? formatMessageContent(message.content)
                    : message.content
                  }
                </div>
                
                {/* Bot message actions */}
                {message.type === 'bot' && (
                  <div className="flex items-center justify-between mt-3 pt-2 border-t border-gray-700/30">
                    <div className="flex items-center space-x-2">
                      {/* Helpful buttons */}
                      <div className="flex items-center space-x-1">
                        <button
                          onClick={() => markMessageHelpful(message.id, true)}
                          className={cn(
                            "p-1 rounded transition-colors",
                            message.helpful === true
                              ? "text-green-400 bg-green-400/20"
                              : "text-gray-500 hover:text-green-400"
                          )}
                          title="Mark as helpful"
                        >
                          <ThumbsUp className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => markMessageHelpful(message.id, false)}
                          className={cn(
                            "p-1 rounded transition-colors",
                            message.helpful === false
                              ? "text-red-400 bg-red-400/20"
                              : "text-gray-500 hover:text-red-400"
                          )}
                          title="Mark as not helpful"
                        >
                          <ThumbsDown className="w-3 h-3" />
                        </button>
                      </div>

                      {/* Copy button */}
                      <button
                        onClick={() => copyToClipboard(message.content)}
                        className="text-gray-500 hover:text-white p-1 rounded transition-colors"
                        title="Copy message"
                      >
                        <Copy className="w-3 h-3" />
                      </button>
                    </div>

                    {/* Export payloads button */}
                    {message.payloads && message.payloads.length > 0 && (
                      <button
                        onClick={() => exportPayloads(message.payloads!)}
                        className="text-xs px-2 py-1 bg-cyan-500/20 text-cyan-400 rounded-lg hover:bg-cyan-500/30 transition-colors"
                      >
                        Export Payloads
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
          
          {/* Loading indicator */}
          {isLoading && (
            <div className="flex justify-start">
              <div className="bg-gray-800/80 rounded-2xl px-4 py-3 border border-gray-700/50">
                <div className="flex items-center space-x-2">
                  <div className="flex space-x-1">
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" />
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }} />
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                  </div>
                  <span className="text-gray-400 text-xs">Thinking...</span>
                </div>
              </div>
            </div>
          )}
          
          <div ref={messagesEndRef} />
        </div>

        {/* Input */}
        <div className="p-4 border-t border-gray-700/50 bg-gray-800/30">
          <div className="flex items-center space-x-2">
            <div className="flex-1 relative">
              <input
                ref={inputRef}
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Ask about vulnerabilities, payloads, or techniques..."
                className="w-full bg-gray-700/50 text-white placeholder-gray-400 rounded-xl px-4 py-2 pr-10 border border-gray-600/50 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 focus:outline-none transition-colors"
                disabled={isLoading}
              />
              
              {/* Send button */}
              <button
                onClick={handleSendMessage}
                disabled={!inputValue.trim() || isLoading}
                className="absolute right-2 top-1/2 transform -translate-y-1/2 p-1.5 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 disabled:from-gray-600 disabled:to-gray-600 rounded-lg transition-all duration-200 disabled:cursor-not-allowed"
              >
                <Send className="w-4 h-4 text-white" />
              </button>
            </div>
          </div>
          
          <div className="text-xs text-gray-500 mt-2 text-center">
            Press Enter to send • Shift+Enter for new line
          </div>
        </div>
      </div>
    </div>
  );
};