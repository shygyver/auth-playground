export interface ClientData {
  clientId: string;
  clientSecret?: string;
  allowedScopes: string[];
  grantTypes: string[];
  redirectUris: string[];
  [key: string]: unknown;
}

export interface UserData {
  id: string;
  username: string;
  password: string;
  email: string;
  fullName: string;
  [key: string]: unknown;
}

interface CodeData {
  clientId: string;
  scope: string[];
  userId: string;
  expiresAt: number;
  codeChallenge?: string | undefined;
  nonce?: string | undefined;
  [key: string]: unknown;
}

interface RefreshTokenData {
  clientId: string;
  userId: string;
  scope: string[];
  expiresAt: number;
  [key: string]: unknown;
}

interface SessionData {
  userId: string;
  expiresAt: number;
  [key: string]: unknown;
}

const clients: ClientData[] = [
  {
    clientId: "example-client",
    clientSecret: "s3cr3tK3y123!",
    allowedScopes: ["content:read", "content:write"],
    grantTypes: ["authorization_code", "refresh_token", "client_credentials"],
    redirectUris: ["http://localhost:3000/callback"],
    registeredCertificate: "h09UV0f9_7N34ujf5jpjdeQptjIJF2OCadewXoeDiYA",
  },
];

const users: UserData[] = [
  {
    id: "user-1234",
    username: "user",
    password: "crossterm",
    email: "user@email.com",
    fullName: "User FullName",
  },
];

const codeStorage: Map<string, CodeData> = new Map();

const refreshTokenStorage: Map<string, RefreshTokenData> = new Map();

const sessionStorage: Map<string, SessionData> = new Map();

export async function findClientById(clientId: string): Promise<ClientData | undefined> {
  return Promise.resolve(clients.find((client) => client.clientId === clientId));
}

export async function findUserById(id: string): Promise<UserData | undefined> {
  return Promise.resolve(users.find((user) => user.id === id));
}

export async function findUserByUsername(username: string): Promise<UserData | undefined> {
  return Promise.resolve(users.find((user) => user.username === username));
}

export async function findUserByCredentials(
  username: string,
  password: string
): Promise<UserData | undefined> {
  return Promise.resolve(
    users.find((user) => user.username === username && user.password === password)
  );
}

export async function storeCode(code: string, data: CodeData): Promise<void> {
  codeStorage.set(code, data);
}

export async function getCodeData(code: string): Promise<CodeData | undefined> {
  return codeStorage.get(code);
}

export async function deleteCode(code: string): Promise<void> {
  codeStorage.delete(code);
}

export async function storeRefreshToken(token: string, data: RefreshTokenData): Promise<void> {
  refreshTokenStorage.set(token, data);
}

export async function getRefreshTokenData(token: string): Promise<RefreshTokenData | undefined> {
  return refreshTokenStorage.get(token);
}

export async function deleteRefreshToken(token: string): Promise<void> {
  refreshTokenStorage.delete(token);
}

export async function storeSession(sessionId: string, data: SessionData): Promise<void> {
  sessionStorage.set(sessionId, data);
}

export async function getSessionData(sessionId: string): Promise<SessionData | undefined> {
  return sessionStorage.get(sessionId);
}

export async function deleteSession(sessionId: string): Promise<void> {
  sessionStorage.delete(sessionId);
}
