# Adoaler JavaScript SDK

[![npm version](https://badge.fury.io/js/%40adoaler%2Fsdk.svg)](https://badge.fury.io/js/%40adoaler%2Fsdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SDK oficial JavaScript/TypeScript para integração com o Adoaler Security Platform.

## Instalação

```bash
# npm
npm install @adoaler/sdk

# yarn
yarn add @adoaler/sdk

# pnpm
pnpm add @adoaler/sdk
```

### Via CDN (Browser)

```html
<script src="https://cdn.adoaler.com/sdk/v2/adoaler.min.js"></script>
```

## Quick Start

### Node.js / Server-side

```typescript
import { Adoaler } from '@adoaler/sdk';

const client = new Adoaler({
  apiKey: 'sua_api_key',
  environment: 'production'
});

// Verificar IP
const ipResult = await client.ip.check('203.0.113.42');
console.log(`Risk Score: ${ipResult.riskScore}`);
console.log(`Risk Level: ${ipResult.riskLevel}`);

// Verificar fraude em transação
const fraudResult = await client.fraud.checkTransaction({
  transactionId: 'txn_123',
  amount: 199.99,
  currency: 'BRL',
  userId: 'user_123',
  ip: '203.0.113.42'
});

if (fraudResult.recommendation === 'decline') {
  console.log('Transação bloqueada');
}
```

### Browser / Client-side

```typescript
import { AdoalerClient } from '@adoaler/sdk/browser';

const client = new AdoalerClient({
  publicKey: 'pk_sua_public_key',
  environment: 'production'
});

// Coletar fingerprint do dispositivo
const fingerprint = await client.device.getFingerprint();

// Enviar para seu backend
await fetch('/api/verify', {
  method: 'POST',
  body: JSON.stringify({
    fingerprint: fingerprint.hash,
    visitorId: fingerprint.visitorId
  })
});
```

## Funcionalidades

### IP Intelligence (Server-side)

```typescript
// Verificação de IP
const ipInfo = await client.ip.check('203.0.113.42');

// Propriedades disponíveis
ipInfo.ip;           // IP verificado
ipInfo.riskScore;    // Score de risco (0-100)
ipInfo.riskLevel;    // 'critical' | 'high' | 'medium' | 'low'
ipInfo.isVpn;        // É VPN?
ipInfo.isProxy;      // É proxy?
ipInfo.isTor;        // É Tor?
ipInfo.isDatacenter; // É datacenter?
ipInfo.country;      // País (código ISO)
ipInfo.city;         // Cidade
ipInfo.asn;          // ASN
ipInfo.organization; // Organização

// Verificação em lote
const results = await client.ip.checkBatch([
  '203.0.113.42',
  '198.51.100.23'
]);
```

### Device Fingerprinting (Browser)

```typescript
// Coletar fingerprint
const fingerprint = await client.device.getFingerprint();

console.log(fingerprint.hash);        // Hash único
console.log(fingerprint.visitorId);   // ID persistente
console.log(fingerprint.components);  // Componentes coletados
console.log(fingerprint.confidence);  // Confiança (0-1)

// Opções avançadas
const fingerprint = await client.device.getFingerprint({
  extendedResult: true,
  debug: false,
  timeout: 5000
});
```

### Bot Detection

```typescript
// Client-side: coletar sinais comportamentais
const behaviorSignals = await client.behavior.collect({
  duration: 10000, // Coletar por 10 segundos
  events: ['mouse', 'keyboard', 'touch', 'scroll']
});

// Server-side: verificar se é bot
const botCheck = await client.bot.detect({
  fingerprint: 'fp_hash',
  userAgent: req.headers['user-agent'],
  ip: req.ip,
  behavior: behaviorSignals
});

botCheck.isBot;           // boolean
botCheck.botType;         // 'crawler' | 'scraper' | 'automation' | null
botCheck.confidence;      // 0-1
botCheck.humanScore;      // 0-100
botCheck.signals;         // Sinais detectados
```

### Fraud Detection (Server-side)

```typescript
const fraudCheck = await client.fraud.checkTransaction({
  transactionId: 'txn_123',
  amount: 199.99,
  currency: 'BRL',
  userId: 'user_123',
  deviceFingerprint: 'fp_hash',
  ip: '203.0.113.42',
  email: 'user@example.com',
  metadata: {
    productCategory: 'electronics',
    paymentMethod: 'credit_card'
  }
});

fraudCheck.riskScore;       // 0-100
fraudCheck.riskLevel;       // 'critical' | 'high' | 'medium' | 'low'
fraudCheck.recommendation;  // 'approve' | 'review' | 'decline'
fraudCheck.signals;         // Sinais de risco
fraudCheck.rulesTriggered;  // Regras acionadas

// Reportar fraude confirmada (feedback)
await client.fraud.report({
  transactionId: 'txn_123',
  isFraud: true,
  fraudType: 'account_takeover'
});
```

### User Risk

```typescript
const userRisk = await client.user.getRisk('user_123');

userRisk.riskScore;      // Score de risco
userRisk.trustScore;     // Score de confiança
userRisk.riskFactors;    // Fatores de risco
userRisk.deviceCount;    // Número de dispositivos
userRisk.anomalies;      // Anomalias detectadas

// Listar eventos do usuário
const events = await client.user.getEvents('user_123', {
  limit: 100,
  eventTypes: ['login', 'transaction']
});
```

### Events

```typescript
// Registrar evento
await client.events.track({
  eventType: 'login',
  userId: 'user_123',
  ip: '203.0.113.42',
  deviceFingerprint: 'fp_hash',
  metadata: {
    method: 'password',
    success: true
  }
});

// Buscar eventos
const events = await client.events.search({
  startDate: '2025-11-01',
  endDate: '2025-11-29',
  eventTypes: ['login', 'transaction'],
  riskLevel: 'high',
  limit: 100
});
```

## Integração com Frameworks

### Express.js

```typescript
import express from 'express';
import { adoalerMiddleware } from '@adoaler/sdk/express';

const app = express();

// Middleware global
app.use(adoalerMiddleware({
  apiKey: 'sua_api_key',
  blockHighRisk: true,
  skipPaths: ['/health', '/public']
}));

// Ou por rota
app.post('/checkout', 
  adoalerMiddleware({ apiKey: 'sua_api_key' }),
  (req, res) => {
    const security = req.adoaler;
    if (security.riskLevel === 'high') {
      return res.status(403).json({ error: 'Blocked' });
    }
    // ...
  }
);
```

### Next.js

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { AdoalerEdge } from '@adoaler/sdk/edge';

const client = new AdoalerEdge({ apiKey: process.env.ADOALER_API_KEY! });

export async function middleware(request: NextRequest) {
  const ip = request.ip || request.headers.get('x-forwarded-for');
  
  const check = await client.ip.check(ip);
  
  if (check.riskLevel === 'critical') {
    return NextResponse.json({ error: 'Blocked' }, { status: 403 });
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: ['/api/:path*', '/checkout/:path*']
};
```

### React Integration

```tsx
import { AdoalerProvider, useAdoaler } from '@adoaler/sdk/react';

// App.tsx
function App() {
  return (
    <AdoalerProvider publicKey="pk_sua_public_key">
      <YourApp />
    </AdoalerProvider>
  );
}

// Component
function CheckoutForm() {
  const { getFingerprint, isReady } = useAdoaler();
  
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    const fingerprint = await getFingerprint();
    
    await fetch('/api/checkout', {
      method: 'POST',
      body: JSON.stringify({
        ...formData,
        deviceFingerprint: fingerprint.hash
      })
    });
  };
  
  if (!isReady) return <Loading />;
  
  return <form onSubmit={handleSubmit}>...</form>;
}
```

### Vue.js Integration

```typescript
// main.ts
import { createApp } from 'vue';
import { AdoalerPlugin } from '@adoaler/sdk/vue';

const app = createApp(App);
app.use(AdoalerPlugin, { publicKey: 'pk_sua_public_key' });

// Component
<script setup>
import { useAdoaler } from '@adoaler/sdk/vue';

const { getFingerprint } = useAdoaler();

const handleCheckout = async () => {
  const fp = await getFingerprint();
  // enviar para backend
};
</script>
```

## TypeScript

O SDK inclui tipos TypeScript completos:

```typescript
import type {
  IPCheckResult,
  DeviceFingerprint,
  BotDetectionResult,
  FraudCheckResult,
  UserRiskResult,
  AdoalerConfig
} from '@adoaler/sdk';
```

## Tratamento de Erros

```typescript
import {
  AdoalerError,
  AuthenticationError,
  RateLimitError,
  ValidationError,
  NetworkError
} from '@adoaler/sdk';

try {
  const result = await client.ip.check('203.0.113.42');
} catch (error) {
  if (error instanceof RateLimitError) {
    console.log(`Rate limit. Retry após: ${error.retryAfter}s`);
  } else if (error instanceof AuthenticationError) {
    console.log('Chave de API inválida');
  } else if (error instanceof ValidationError) {
    console.log('Dados inválidos:', error.errors);
  } else if (error instanceof NetworkError) {
    console.log('Erro de rede');
  } else if (error instanceof AdoalerError) {
    console.log('Erro geral:', error.message);
  }
}
```

## Webhooks

```typescript
import { WebhookHandler } from '@adoaler/sdk';

const webhook = new WebhookHandler({
  signingSecret: 'seu_webhook_secret'
});

// Express example
app.post('/webhook', express.raw({ type: '*/*' }), (req, res) => {
  try {
    const event = webhook.verifyAndParse(
      req.body,
      req.headers['x-adoaler-signature'] as string
    );
    
    switch (event.type) {
      case 'threat.detected':
        handleThreat(event.data);
        break;
      case 'device.suspicious':
        handleSuspiciousDevice(event.data);
        break;
    }
    
    res.json({ received: true });
  } catch (error) {
    res.status(400).json({ error: 'Invalid signature' });
  }
});
```

## Configuração Avançada

```typescript
const client = new Adoaler({
  apiKey: 'sua_api_key',
  environment: 'production',  // 'production' | 'sandbox'
  timeout: 30000,             // timeout em ms
  maxRetries: 3,              // tentativas em caso de falha
  retryDelay: 1000,           // delay entre tentativas
  debug: false,               // modo debug
  baseUrl: undefined          // URL customizada (para self-hosted)
});
```

## Documentação

- **Docs**: https://docs.adoaler.com/sdk/javascript
- **API Reference**: https://docs.adoaler.com/api
- **Examples**: https://github.com/adoaler/js-sdk/examples
- **TypeScript Docs**: https://docs.adoaler.com/sdk/javascript/typescript

## Suporte

- **Email**: support@adoaler.com
- **GitHub Issues**: https://github.com/adoaler/js-sdk/issues

## Licença

MIT License - veja [LICENSE](LICENSE) para detalhes.


