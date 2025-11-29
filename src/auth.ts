/**
 * Adoaler Auth SDK - Authentication & Session Management
 */

export interface AuthConfig {
  apiKey: string;
  secretKey: string;
  baseUrl?: string;
  sessionTTL?: number;
  enableMFA?: boolean;
  timeout?: number;
}

export interface Session {
  sessionId: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  ipAddress?: string;
  userAgent?: string;
  deviceId?: string;
  metadata?: Record<string, unknown>;
  isActive: boolean;
}

export interface MFASetup {
  method: MFAMethod;
  secret?: string;
  qrCodeUrl?: string;
  backupCodes?: string[];
}

export type MFAMethod = 'totp' | 'sms' | 'email';

export interface LoginOptions {
  email: string;
  password: string;
  metadata?: Record<string, string>;
}

export class AdoalerAuth {
  private config: Required<AuthConfig>;
  private sessions: Map<string, Session> = new Map();

  constructor(config: AuthConfig) {
    this.config = {
      apiKey: config.apiKey,
      secretKey: config.secretKey,
      baseUrl: config.baseUrl || 'https://auth.adoaler.com/v1',
      sessionTTL: config.sessionTTL || 86400,
      enableMFA: config.enableMFA || false,
      timeout: config.timeout || 30000,
    };
  }

  async login(options: LoginOptions): Promise<Session> {
    const payload: Record<string, unknown> = {
      email: options.email,
      password: options.password,
    };
    if (options.metadata) {
      payload.metadata = options.metadata;
    }

    const response = await this.sendRequest('/auth/login', payload);
    const session = this.parseSession(response);
    this.sessions.set(session.sessionId, session);
    return session;
  }

  async logout(sessionId: string): Promise<boolean> {
    try {
      await this.sendRequest('/auth/logout', { session_id: sessionId });
      this.sessions.delete(sessionId);
      return true;
    } catch {
      return false;
    }
  }

  async validateSession(sessionId: string): Promise<Session | null> {
    try {
      const response = await this.sendRequest('/auth/session/validate', {
        session_id: sessionId,
      });
      return this.parseSession(response);
    } catch {
      return null;
    }
  }

  async refreshSession(sessionId: string): Promise<Session | null> {
    try {
      const response = await this.sendRequest('/auth/session/refresh', {
        session_id: sessionId,
      });
      const session = this.parseSession(response);
      this.sessions.set(session.sessionId, session);
      return session;
    } catch {
      return null;
    }
  }

  async setupMFA(userId: string, method: MFAMethod): Promise<MFASetup> {
    const response = await this.sendRequest('/auth/mfa/setup', {
      user_id: userId,
      method,
    });
    return {
      method: response.method,
      secret: response.secret,
      qrCodeUrl: response.qr_code_url,
      backupCodes: response.backup_codes,
    };
  }

  async verifyMFA(userId: string, code: string): Promise<boolean> {
    try {
      await this.sendRequest('/auth/mfa/verify', { user_id: userId, code });
      return true;
    } catch {
      return false;
    }
  }

  async sendMFACode(userId: string, method: MFAMethod): Promise<boolean> {
    try {
      await this.sendRequest('/auth/mfa/send', { user_id: userId, method });
      return true;
    } catch {
      return false;
    }
  }

  // Utility methods
  static async hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  static generateSessionId(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
  }

  static async generateDeviceFingerprint(): Promise<string> {
    if (typeof navigator === 'undefined') return '';
    const components = [
      navigator.userAgent,
      navigator.language,
      screen?.width,
      screen?.height,
      screen?.colorDepth,
      new Date().getTimezoneOffset(),
    ];
    const data = components.join('|');
    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Cookie helpers
  static getSessionFromCookie(): string | null {
    if (typeof document === 'undefined') return null;
    const match = document.cookie.match(/adoaler_session=([^;]+)/);
    return match ? match[1] : null;
  }

  static setSessionCookie(sessionId: string, expiresAt: number, secure = true): void {
    if (typeof document === 'undefined') return;
    const expires = new Date(expiresAt * 1000).toUTCString();
    const secureFlag = secure ? 'secure; ' : '';
    document.cookie = `adoaler_session=${sessionId}; expires=${expires}; path=/; ${secureFlag}samesite=lax`;
  }

  static clearSessionCookie(): void {
    if (typeof document === 'undefined') return;
    document.cookie = 'adoaler_session=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
  }

  // Express middleware
  middleware() {
    return async (req: any, res: any, next: any) => {
      const sessionId = req.headers['x-session-id'] || req.cookies?.adoaler_session;
      if (!sessionId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      const session = await this.validateSession(sessionId);
      if (!session) {
        res.status(401).json({ error: 'Invalid session' });
        return;
      }
      req.userId = session.userId;
      req.session = session;
      next();
    };
  }

  private async sendRequest(endpoint: string, payload: Record<string, unknown>): Promise<any> {
    const body = JSON.stringify(payload);
    const signature = await this.signRequest(body);

    const response = await fetch(`${this.config.baseUrl}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Adoaler-Key': this.config.apiKey,
        'X-Adoaler-Signature': signature,
      },
      body,
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (response.status === 401) {
      throw new Error('Invalid credentials');
    }
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    return response.json();
  }

  private async signRequest(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.config.secretKey),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  private parseSession(data: any): Session {
    return {
      sessionId: data.session_id,
      userId: data.user_id,
      createdAt: data.created_at || Math.floor(Date.now() / 1000),
      expiresAt: data.expires_at || Math.floor(Date.now() / 1000) + this.config.sessionTTL,
      ipAddress: data.ip_address,
      userAgent: data.user_agent,
      deviceId: data.device_id,
      metadata: data.metadata,
      isActive: data.is_active !== false,
    };
  }
}

export default AdoalerAuth;
