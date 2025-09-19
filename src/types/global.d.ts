// Global type declarations to resolve TypeScript errors
declare module 'estree' {
  export interface Node {
    type: string;
  }
}

declare module 'json-schema' {
  export interface Schema {
    type?: string;
  }
}

// Additional Node.js types if needed
declare namespace NodeJS {
  interface ProcessEnv {
    NODE_ENV: string;
  }
}