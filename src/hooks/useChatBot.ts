import { useState, useEffect, useCallback } from 'react';
import { vulnerabilities, challenges, getContextualHelp, searchKnowledgeBase, ChatContext } from '@/data/chatKnowledgeBase';
import { useLocation } from 'react-router-dom';

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

  useEffect(() => {
    if (state.context && state.messages.length > 0) {
      // Update greeting based on context change
      const lastMessage = state.messages[state.messages.length - 1];
      if (lastMessage.type === 'bot' && lastMessage.content.includes('Good')) {
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
  }, [state.context]);

  const generateGreeting = (context: ChatContext): string => {
    const time = new Date().getHours();
    const timeGreeting = time < 12 ? 'Good morning' : time < 18 ? 'Good afternoon' : 'Good evening';
    
    let greeting = `${timeGreeting}! I'm your CyberLab Security Assistant. 🛡️\n\n`;
    
    if (context.currentModule) {
      const moduleName = context.currentModule.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase());
      greeting += `I see you're working on the ${moduleName} challenge. `;
      
      if (context.difficulty) {
        greeting += `This is a ${context.difficulty} level challenge. `;
      }
      
      greeting += `\n\nI can help you with:`;
    } else {
      greeting += `I can help you with various cybersecurity challenges including:`;
    }
    
    greeting += `\n• Vulnerability exploitation techniques\n• Payload suggestions and examples\n• Troubleshooting common errors\n• Security best practices\n\nWhat would you like to explore today?`;
    
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
    if (content.includes('Good') && state.messages.some(msg => msg.content.includes('Good'))) {
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
        content: `Here are some SQL injection payloads to try:\n\n${sqlVuln?.payloads.map((p, i) => `${i + 1}. \`${p}\``).join('\n')}\n\nRemember to URL-encode special characters when testing in a browser. Start with the basic OR condition and work your way up to more complex UNION attacks.`,
        payloads: sqlVuln?.payloads
      };
    }

    if (input.includes('xss') || input.includes('cross-site')) {
      const xssVuln = vulnerabilities.find(v => v.id === 'xss-reflected');
      return {
        content: `Here are some XSS payloads to test:\n\n${xssVuln?.payloads.map((p, i) => `${i + 1}. \`${p}\``).join('\n')}\n\nTry these in different contexts - URL parameters, form fields, and headers. If one doesn't work, try the others!`,
        payloads: xssVuln?.payloads
      };
    }

    if (input.includes('command') && input.includes('injection')) {
      const cmdVuln = vulnerabilities.find(v => v.id === 'command-injection');
      return {
        content: `Here are command injection payloads:\n\n${cmdVuln?.payloads.map((p, i) => `${i + 1}. \`${p}\``).join('\n')}\n\nStart with simple commands like \`whoami\` or \`ls\` to verify injection works, then try more complex commands.`,
        payloads: cmdVuln?.payloads
      };
    }

    // Check for error-related questions
    if (input.includes('error') || input.includes('not working') || input.includes('failed')) {
      return {
        content: `I can help you troubleshoot! Here are some common issues and solutions:\n\n• **SQL Syntax Error**: Check quote placement and comment syntax\n• **Script Not Executing**: Try different XSS contexts or bypass CSP\n• **Command Not Found**: Verify the command exists on the target system\n• **Access Denied**: You may need different privileges or file paths\n\nCan you share the specific error message you're seeing?`
      };
    }

    // Check for help requests
    if (input.includes('help') || input.includes('how') || input.includes('what')) {
      const suggestions = getContextualHelp(context);
      if (suggestions.length > 0) {
        return {
          content: `Based on your current challenge, here are some suggestions:\n\n${suggestions.map((s, i) => `${i + 1}. ${s}`).join('\n')}\n\nWould you like specific payloads for any of these techniques?`
        };
      }
    }

    // Search knowledge base
    const searchResults = searchKnowledgeBase(userInput);
    if (searchResults.length > 0) {
      const result = searchResults[0];
      if ('payloads' in result) {
        return {
          content: `I found information about **${result.name}**:\n\n${result.description}\n\nHere are some payloads to try:\n${result.payloads.slice(0, 3).map((p, i) => `${i + 1}. \`${p}\``).join('\n')}`,
          payloads: result.payloads.slice(0, 3)
        };
      } else {
        return {
          content: `I found the **${result.name}** challenge. Here are some hints:\n\n${result.hints.map((h, i) => `${i + 1}. ${h}`).join('\n')}`
        };
      }
    }

    // Default response with contextual suggestions
    const suggestions = getContextualHelp(context);
    let defaultResponse = `I'm here to help with your cybersecurity challenges! You can ask me about:\n\n• Specific vulnerabilities (SQL injection, XSS, etc.)\n• Payload examples and techniques\n• Troubleshooting errors\n• Security best practices`;
    
    if (suggestions.length > 0) {
      defaultResponse += `\n\nBased on your current module, you might want to try:\n${suggestions.slice(0, 2).map(s => `• ${s}`).join('\n')}`;
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
      addBotMessage('✅ Payloads copied to clipboard!');
    }).catch(() => {
      addBotMessage('❌ Failed to copy payloads. Please copy them manually.');
    });
  }, [addBotMessage]);

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