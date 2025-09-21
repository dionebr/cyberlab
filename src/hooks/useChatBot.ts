import { useState, useEffect, useCallback } from 'react';
import { vulnerabilities, challenges, getContextualHelp, searchKnowledgeBase, ChatContext } from '@/data/chatKnowledgeBase';
import { useLocation } from 'react-router-dom';
import { useLanguageContext } from '@/contexts/LanguageContext';

export interface ChatMessage {
  id: string;
  type: 'user' | 'bot' | 'system';
  content: string;
  timestamp: Date;
  payloads?: string[];
  helpful?: boolean;
  context?: string;
}

export interface ChatState {
  messages: ChatMessage[];
  isOpen: boolean;
  isLoading: boolean;
  hasUnreadMessages: boolean;
  context: ChatContext;
}

const STORAGE_KEY = 'cyberlab-chat-history';

export const useChatBot = () => {
  const location = useLocation();
  const { t } = useLanguageContext();
  const [state, setState] = useState<ChatState>({
    messages: [],
    isOpen: false,
    isLoading: false,
    hasUnreadMessages: false,
    context: {}
  });

  // Load chat history from localStorage
  useEffect(() => {
    const savedHistory = localStorage.getItem(STORAGE_KEY);
    if (savedHistory) {
      try {
        const parsed = JSON.parse(savedHistory);
        setState(prev => ({
          ...prev,
          messages: parsed.map((msg: any) => ({
            ...msg,
            timestamp: new Date(msg.timestamp)
          }))
        }));
      } catch (error) {
        console.error('Error loading chat history:', error);
      }
    }
  }, []);

  // Save chat history to localStorage
  const saveHistory = useCallback((messages: ChatMessage[]) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(messages));
    } catch (error) {
      console.error('Error saving chat history:', error);
    }
  }, []);

  // Update context based on current route
  useEffect(() => {
    const updateContext = () => {
      const pathSegments = location.pathname.split('/');
      const newContext: ChatContext = {};

      // Extract module from URL
      if (pathSegments.includes('challenges') && pathSegments.length > 2) {
        newContext.currentModule = pathSegments[2];
      }

      // Extract difficulty from URL params
      const urlParams = new URLSearchParams(location.search);
      const difficulty = urlParams.get('difficulty') || urlParams.get('level');
      if (difficulty) {
        newContext.difficulty = difficulty;
      }

      setState(prev => ({
        ...prev,
        context: newContext
      }));
    };

    updateContext();
  }, [location]);

  // Initialize chat with greeting
  useEffect(() => {
    const initializeChat = () => {
      if (state.messages.length === 0) {
        const greeting = generateGreeting(state.context);
        setTimeout(() => addBotMessage(greeting), 500);
      }
    };
    initializeChat();
  }, []);

  // Regenerate greeting when language changes
  useEffect(() => {
    if (state.messages.length > 0) {
      const firstMessage = state.messages[0];
      const isGreeting = firstMessage.type === 'bot' && (
        firstMessage.content.includes('Good') || 
        firstMessage.content.includes('Bom') ||
        firstMessage.content.includes('Buenos') ||
        firstMessage.content.includes('🛡️')
      );
      
      if (isGreeting) {
        const newGreeting = generateGreeting(state.context);
        setState(prev => {
          const updatedMessages = [...prev.messages];
          updatedMessages[0] = {
            ...firstMessage,
            content: newGreeting
          };
          saveHistory(updatedMessages);
          return {
            ...prev,
            messages: updatedMessages
          };
        });
      }
    }
  }, [t]);  // Trigger when language changes

  useEffect(() => {
    if (state.context && state.messages.length > 0) {
      // Update greeting based on context change
      const lastMessage = state.messages[state.messages.length - 1];
      // Check if it's a greeting message (contains assistant intro or greeting)
      const isGreeting = lastMessage.type === 'bot' && (
        lastMessage.content.includes('Good') || 
        lastMessage.content.includes('Bom') ||
        lastMessage.content.includes('Buenos') ||
        lastMessage.content.includes('Security Assistant') ||
        lastMessage.content.includes('Assistente de Segurança') ||
        lastMessage.content.includes('Asistente de Seguridad') ||
        lastMessage.content.includes('🛡️')
      );
      
      if (isGreeting) {
        const newGreeting = generateGreeting(state.context);
        // Update the last message if it's a greeting
        setState(prev => {
          const updatedMessages = [...prev.messages];
          updatedMessages[updatedMessages.length - 1] = {
            ...lastMessage,
            content: newGreeting
          };
          saveHistory(updatedMessages);
          return {
            ...prev,
            messages: updatedMessages
          };
        });
      }
    }
  }, [state.context, t]);

  const generateGreeting = (context: ChatContext): string => {
    const time = new Date().getHours();
    const timeGreeting = time < 12 ? t('chat.greeting_morning') : time < 18 ? t('chat.greeting_afternoon') : t('chat.greeting_evening');
    
    let greeting = `${timeGreeting}! ${t('chat.assistant_intro')}\n\n`;
    
    if (context.currentModule) {
      const moduleName = context.currentModule.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase());
      greeting += t('chat.working_on_challenge').replace('{module}', moduleName) + ' ';
      
      if (context.difficulty) {
        greeting += t('chat.difficulty_level').replace('{difficulty}', context.difficulty) + ' ';
      }
      
      greeting += `\n\n${t('chat.can_help_with')}`;
    } else {
      greeting += `${t('chat.can_help_with')}`;
    }
    
    greeting += `\n\n${t('chat.help_topics')}\n\n${t('chat.what_explore')}`;
    
    return greeting;
  };

  const addMessage = useCallback((message: Omit<ChatMessage, 'id' | 'timestamp'>) => {
    const newMessage: ChatMessage = {
      ...message,
      id: Date.now().toString(),
      timestamp: new Date()
    };

    setState(prev => {
      const newMessages = [...prev.messages, newMessage];
      saveHistory(newMessages);
      return {
        ...prev,
        messages: newMessages,
        hasUnreadMessages: !prev.isOpen && message.type === 'bot'
      };
    });

    return newMessage.id;
  }, [saveHistory]);

  const addBotMessage = useCallback((content: string, payloads?: string[]) => {
    // Prevent duplicate greetings
    const isGreeting = content.includes('Good') || content.includes('Bom') || content.includes('Buenos') || content.includes('🛡️');
    const hasExistingGreeting = state.messages.some(msg => 
      msg.content.includes('Good') || msg.content.includes('Bom') || msg.content.includes('Buenos') || msg.content.includes('🛡️')
    );
    
    if (isGreeting && hasExistingGreeting) {
      return;
    }
    return addMessage({
      type: 'bot',
      content,
      payloads
    });
  }, [addMessage, state.messages]);

  const addUserMessage = useCallback((content: string) => {
    return addMessage({
      type: 'user',
      content
    });
  }, [addMessage]);

  const processUserMessage = useCallback(async (userInput: string) => {
    setState(prev => ({ ...prev, isLoading: true }));

    // Add user message
    addUserMessage(userInput);

    // Simulate thinking time
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Process the message and generate response
    const response = await generateBotResponse(userInput, state.context);
    
    addBotMessage(response.content, response.payloads);

    setState(prev => ({ ...prev, isLoading: false }));
  }, [state.context, addUserMessage, addBotMessage]);

  const generateBotResponse = async (userInput: string, context: ChatContext) => {
    const input = userInput.toLowerCase();
    
    // Check for specific vulnerability questions
    if (input.includes('sql') && input.includes('injection')) {
      const sqlVuln = vulnerabilities.find(v => v.id === 'sql-basic');
      return {
        content: `${t('chat.sql_injection_help')}\n\n${sqlVuln?.payloads.map((p, i) => `${i + 1}. \`${p}\``).join('\n')}\n\n${t('chat.sql_remember')}`,
        payloads: sqlVuln?.payloads
      };
    }

    if (input.includes('xss') || input.includes('cross-site')) {
      const xssVuln = vulnerabilities.find(v => v.id === 'xss-reflected');
      return {
        content: `${t('chat.xss_help')}\n\n${xssVuln?.payloads.map((p, i) => `${i + 1}. \`${p}\``).join('\n')}\n\n${t('chat.xss_try_contexts')}`,
        payloads: xssVuln?.payloads
      };
    }

    if (input.includes('command') && input.includes('injection')) {
      const cmdVuln = vulnerabilities.find(v => v.id === 'command-injection');
      return {
        content: `${t('chat.command_injection_help')}\n\n${cmdVuln?.payloads.map((p, i) => `${i + 1}. \`${p}\``).join('\n')}\n\n${t('chat.command_start_simple')}`,
        payloads: cmdVuln?.payloads
      };
    }

    // Check for TOTP/2FA questions
    if (input.includes('totp') || input.includes('2fa') || input.includes('two factor') || input.includes('authenticator')) {
      const totpVuln = vulnerabilities.find(v => v.id === 'totp-2fa');
      return {
        content: `${t('chat.totp_2fa_help')}\n\n${totpVuln?.payloads.map((p, i) => `${i + 1}. \`${p}\``).join('\n')}\n\n${t('chat.totp_check_secrets')}`,
        payloads: totpVuln?.payloads
      };
    }

    // Check for JWT questions
    if (input.includes('jwt') || input.includes('json web token') || input.includes('token')) {
      const jwtVuln = vulnerabilities.find(v => v.id === 'jwt-auth');
      return {
        content: `${t('chat.jwt_help')}\n\n${jwtVuln?.payloads.map((p, i) => `${i + 1}. \`${p}\``).join('\n')}\n\n${t('chat.jwt_try_algorithms')}`,
        payloads: jwtVuln?.payloads
      };
    }

    // Check for error-related questions
    if (input.includes('error') || input.includes('not working') || input.includes('failed')) {
      return {
        content: `${t('chat.troubleshoot_help')}\n\n${t('chat.common_issues')}\n\n${t('chat.share_error')}`
      };
    }

    // Check for help requests
    if (input.includes('help') || input.includes('how') || input.includes('what')) {
      const suggestions = getContextualHelp(context);
      if (suggestions.length > 0) {
        return {
          content: `${t('chat.contextual_suggestions')}\n\n${suggestions.map((s, i) => `${i + 1}. ${s}`).join('\n')}\n\n${t('chat.want_payloads')}`
        };
      }
    }

    // Search knowledge base
    const searchResults = searchKnowledgeBase(userInput);
    if (searchResults.length > 0) {
      const result = searchResults[0];
      if ('payloads' in result) {
        return {
          content: `${t('chat.found_info').replace('{name}', result.name)}\n\n${result.description}\n\n${t('chat.try_payloads')}\n${result.payloads.slice(0, 3).map((p, i) => `${i + 1}. \`${p}\``).join('\n')}`,
          payloads: result.payloads.slice(0, 3)
        };
      } else {
        return {
          content: `${t('chat.found_challenge').replace('{name}', result.name)}\n\n${result.hints.map((h, i) => `${i + 1}. ${h}`).join('\n')}`
        };
      }
    }

    // Default response with contextual suggestions
    const suggestions = getContextualHelp(context);
    let defaultResponse = t('chat.default_help');
    
    if (suggestions.length > 0) {
      defaultResponse += `\n\n${t('chat.based_on_module')}\n${suggestions.slice(0, 2).map(s => `• ${s}`).join('\n')}`;
    }

    return {
      content: defaultResponse
    };
  };

  const toggleChat = useCallback(() => {
    setState(prev => ({
      ...prev,
      isOpen: !prev.isOpen,
      hasUnreadMessages: prev.isOpen ? prev.hasUnreadMessages : false
    }));
  }, []);

  const closeChat = useCallback(() => {
    setState(prev => ({
      ...prev,
      isOpen: false,
      hasUnreadMessages: false
    }));
  }, []);

  const markMessageHelpful = useCallback((messageId: string, helpful: boolean) => {
    setState(prev => {
      const newMessages = prev.messages.map(msg =>
        msg.id === messageId ? { ...msg, helpful } : msg
      );
      saveHistory(newMessages);
      return {
        ...prev,
        messages: newMessages
      };
    });
  }, [saveHistory]);

    const clearHistory = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    setState(prev => ({
      ...prev,
      messages: []
    }));
    
    // Re-add greeting after clearing
    setTimeout(() => {
      const greeting = generateGreeting(state.context);
      addMessage({
        type: 'bot',
        content: greeting
      });
    }, 500);
  }, [state.context]);

  // Clear duplicates on initialization
  useEffect(() => {
    if (state.messages.length > 10) {
      // Clear excessive messages
      localStorage.removeItem(STORAGE_KEY);
      setState(prev => ({
        ...prev,
        messages: []
      }));
    }
  }, []);

  const exportPayloads = useCallback((payloads: string[]) => {
    const text = payloads.join('\n');
    navigator.clipboard.writeText(text).then(() => {
      addBotMessage(t('chat.payloads_copied'));
    }).catch(() => {
      addBotMessage(t('chat.copy_failed'));
    });
  }, [addBotMessage, t]);

  return {
    ...state,
    toggleChat,
    closeChat,
    processUserMessage,
    markMessageHelpful,
    clearHistory,
    exportPayloads
  };
};