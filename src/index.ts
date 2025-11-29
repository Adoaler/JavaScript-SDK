/**
 * Adoaler JavaScript/TypeScript SDK
 * @version 2.0.0
 * @license MIT
 */

// Core Client
export { AdoalerClient } from './client';
export type { AdoalerConfig, ApiResponse } from './client';

// Ads Module
export { AdoalerAds, AdType, BannerSize } from './ads';
export type { AdsConfig, AdUnit, AdResponse } from './ads';

// ID Module (OAuth 2.0 / OIDC)
export { AdoalerID } from './id';
export type { IDConfig, TokenResponse, UserInfo, AuthorizationResult } from './id';

// Auth Module (Sessions & MFA)
export { AdoalerAuth } from './auth';
export type { AuthConfig, Session, MFASetup, MFAMethod, LoginOptions } from './auth';

// Default export
export { AdoalerClient as default } from './client';
