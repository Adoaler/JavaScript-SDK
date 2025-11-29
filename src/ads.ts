/**
 * Adoaler Ads SDK
 */

export interface AdsConfig {
  publisherId: string;
  apiKey: string;
  secretKey: string;
  baseUrl?: string;
  timeout?: number;
}

export enum AdType {
  Banner = 'banner',
  Native = 'native',
  Interstitial = 'interstitial',
  Video = 'video',
  Rewarded = 'rewarded',
}

export enum BannerSize {
  Size320x50 = '320x50',
  Size300x250 = '300x250',
  Size728x90 = '728x90',
  Size160x600 = '160x600',
  Size300x600 = '300x600',
}

export interface AdUnit {
  unitId: string;
  type: AdType;
  size?: BannerSize | string;
  placementId?: string;
  keywords?: string[];
  metadata?: Record<string, string>;
}

export interface AdResponse {
  adId: string;
  type: AdType;
  html?: string;
  imageUrl?: string;
  videoUrl?: string;
  clickUrl: string;
  trackingUrl: string;
  title?: string;
  description?: string;
  cta?: string;
  metadata?: Record<string, unknown>;
}

export class AdoalerAds {
  private config: Required<AdsConfig>;

  constructor(config: AdsConfig) {
    this.config = {
      publisherId: config.publisherId,
      apiKey: config.apiKey,
      secretKey: config.secretKey,
      baseUrl: config.baseUrl || 'https://ads.adoaler.com/v1',
      timeout: config.timeout || 10000,
    };
  }

  async requestAd(unit: AdUnit, userContext: Record<string, string> = {}): Promise<AdResponse> {
    const payload: Record<string, unknown> = {
      publisher_id: this.config.publisherId,
      unit_id: unit.unitId,
      type: unit.type,
      timestamp: Math.floor(Date.now() / 1000),
    };

    if (unit.size) payload.size = unit.size;
    if (unit.placementId) payload.placement_id = unit.placementId;
    if (unit.keywords?.length) payload.keywords = unit.keywords;
    if (Object.keys(userContext).length) payload.user_context = userContext;

    const response = await this.sendRequest('/ads/request', payload);
    return this.parseAdResponse(response);
  }

  async trackImpression(adId: string): Promise<boolean> {
    return this.sendTrackingEvent('/ads/impression', adId, 'impression');
  }

  async trackClick(adId: string): Promise<boolean> {
    return this.sendTrackingEvent('/ads/click', adId, 'click');
  }

  async trackVideoEvent(adId: string, event: string, position: number): Promise<boolean> {
    try {
      await this.sendRequest('/ads/video/event', {
        ad_id: adId,
        event,
        position,
        publisher_id: this.config.publisherId,
        timestamp: Math.floor(Date.now() / 1000),
      });
      return true;
    } catch {
      return false;
    }
  }

  async trackViewability(adId: string, viewablePercent: number, duration: number): Promise<boolean> {
    try {
      await this.sendRequest('/ads/viewability', {
        ad_id: adId,
        viewable_percent: viewablePercent,
        duration,
        publisher_id: this.config.publisherId,
        timestamp: Math.floor(Date.now() / 1000),
      });
      return true;
    } catch {
      return false;
    }
  }

  async verifyCallback(payload: string, signature: string): Promise<boolean> {
    const expected = await this.signRequest(payload);
    return expected === signature;
  }

  generateAdTag(unit: AdUnit): string {
    const params = new URLSearchParams({
      pub: this.config.publisherId,
      unit: unit.unitId,
      type: unit.type,
    });
    if (unit.size) params.set('size', unit.size);
    return `<script src="${this.config.baseUrl}/tag.js?${params}" async></script>`;
  }

  private async sendTrackingEvent(endpoint: string, adId: string, event: string): Promise<boolean> {
    try {
      await this.sendRequest(endpoint, {
        ad_id: adId,
        event,
        publisher_id: this.config.publisherId,
        timestamp: Math.floor(Date.now() / 1000),
      });
      return true;
    } catch {
      return false;
    }
  }

  private async sendRequest(endpoint: string, payload: Record<string, unknown>): Promise<unknown> {
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

  private parseAdResponse(data: any): AdResponse {
    return {
      adId: data.ad_id,
      type: data.type,
      html: data.html,
      imageUrl: data.image_url,
      videoUrl: data.video_url,
      clickUrl: data.click_url,
      trackingUrl: data.tracking_url,
      title: data.title,
      description: data.description,
      cta: data.cta,
      metadata: data.metadata,
    };
  }
}

export default AdoalerAds;
