export type APIErrorEnvelope = {
  error?: {
    code?: unknown;
    requestId?: unknown;
  };
};

export type LoginChallenge = {
  challengeId: string;
  expiresAt: string;
};

export type TokenResponse = {
  token: string;
  tokenType?: string;
  expiresAt: string;
};

export type Me = {
  userId: string;
  systemRole: string;
  issuedAt: string;
  recentTotpAt?: string;
};

export type SpaceRole = "owner" | "editor" | "reader";

export type Space = {
  id: string;
  name: string;
  role: SpaceRole;
};

export type ListResponse<T> = {
  items: T[];
  nextCursor?: string;
};

export type BootstrapResponse = {
  userId: string;
  recoveryCodes: string[];
};
