/**
 * Adoaler ID SDK - OAuth 2.0 / OpenID Connect
 */

export interface IDConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  baseUrl?: string;
  scopes?: string[];
  timeout?: number;
}

export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  refreshToken?: string;
  idToken?: string;
  scope?: string;
}

export interface UserInfo {
  sub: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
  picture?: string;
  locale?: string;
}

export interface AuthorizationResult {
  url: string;
  state: string;
  verifier?: string;
}

export class AdoalerID {
  private config: Required<IDConfig>;
  private pkceStore: Map<string, string> = new Map();

  constructor(config: IDConfig) {
    this.config = {
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri,
      baseUrl: config.baseUrl || 'https://id.adoaler.com',
      scopes: config.scopes || ['openid', 'profile', 'email'],
      timeout: config.timeout || 30000,
    };
  }

  static generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  static async generateCodeChallenge(verifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  static generateState(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
  }

  async getAuthorizationUrl(state: string, usePKCE = true): Promise<AuthorizationResult> {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.config.scopes.join(' '),
      state,
    });

    let verifier: string | undefined;
    if (usePKCE) {
      verifier = AdoalerID.generateCodeVerifier();
      const challenge = await AdoalerID.generateCodeChallenge(verifier);
      params.set('code_challenge', challenge);
      params.set('code_challenge_method', 'S256');
      this.pkceStore.set(state, verifier);
    }

    return {
      url: `${this.config.baseUrl}/oauth/authorize?${params}`,
      state,
      verifier,
    };
  }

  async exchangeCode(code: string, state: string): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      redirect_uri: this.config.redirectUri,
    });

    const verifier = this.pkceStore.get(state);
    if (verifier) {
      params.set('code_verifier', verifier);
      this.pkceStore.delete(state);
    }

    const response = await fetch(`${this.config.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Token exchange failed: ${error}`);
    }

    const data = await response.json();
    return this.parseTokenResponse(data);
  }

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    });

    const response = await fetch(`${this.config.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.status}`);
    }

    const data = await response.json();
    return this.parseTokenResponse(data);
  }

  async getUserInfo(accessToken: string): Promise<UserInfo> {
    const response = await fetch(`${this.config.baseUrl}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      throw new Error(`UserInfo request failed: ${response.status}`);
    }

    const data = await response.json();
    return {
      sub: data.sub,
      name: data.name,
      email: data.email,
      emailVerified: data.email_verified,
      picture: data.picture,
      locale: data.locale,
    };
  }

  async revokeToken(token: string): Promise<boolean> {
    try {
      const params = new URLSearchParams({
        token,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      });

      await fetch(`${this.config.baseUrl}/oauth/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params,
        signal: AbortSignal.timeout(this.config.timeout),
      });
      return true;
    } catch {
      return false;
    }
  }

  getLogoutUrl(idToken: string, postLogoutRedirect?: string): string {
    const params = new URLSearchParams({ id_token_hint: idToken });
    if (postLogoutRedirect) {
      params.set('post_logout_redirect_uri', postLogoutRedirect);
    }
    return `${this.config.baseUrl}/oauth/logout?${params}`;
  }

  // Session storage helpers for browser
  storeState(state: string, verifier?: string): void {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem('adoaler_oauth_state', state);
      if (verifier) {
        sessionStorage.setItem('adoaler_pkce_verifier', verifier);
      }
    }
  }

  retrieveState(): { state: string | null; verifier: string | null } {
    if (typeof sessionStorage === 'undefined') {
      return { state: null, verifier: null };
    }
    const state = sessionStorage.getItem('adoaler_oauth_state');
    const verifier = sessionStorage.getItem('adoaler_pkce_verifier');
    sessionStorage.removeItem('adoaler_oauth_state');
    sessionStorage.removeItem('adoaler_pkce_verifier');
    return { state, verifier };
  }

  private parseTokenResponse(data: any): TokenResponse {
    return {
      accessToken: data.access_token,
      tokenType: data.token_type || 'Bearer',
      expiresIn: data.expires_in || 3600,
      refreshToken: data.refresh_token,
      idToken: data.id_token,
      scope: data.scope,
    };
  }
}

export default AdoalerID;
