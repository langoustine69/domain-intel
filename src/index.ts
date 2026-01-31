import { createAgent } from '@lucid-agents/core';
import { http } from '@lucid-agents/http';
import { createAgentApp } from '@lucid-agents/hono';
import { payments, paymentsFromEnv } from '@lucid-agents/payments';
import { z } from 'zod';

const agent = await createAgent({
  name: 'domain-intel',
  version: '1.0.0',
  description: 'Domain intelligence for AI agents - DNS, SSL, IP geolocation, and HTTP headers in one API',
})
  .use(http())
  .use(payments({ config: paymentsFromEnv() }))
  .build();

const { app, addEntrypoint } = await createAgentApp(agent);

// === HELPER FUNCTIONS ===
async function fetchJSON(url: string, timeout = 10000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (!response.ok) throw new Error(`API error: ${response.status}`);
    return response.json();
  } catch (e: any) {
    clearTimeout(timeoutId);
    throw e;
  }
}

function extractDomain(input: string): string {
  // Remove protocol and path, extract just the domain
  let domain = input.toLowerCase().trim();
  domain = domain.replace(/^https?:\/\//, '');
  domain = domain.replace(/\/.*$/, '');
  domain = domain.replace(/:\d+$/, ''); // Remove port
  return domain;
}

// === FREE ENDPOINT - Overview ===
addEntrypoint({
  key: 'overview',
  description: 'Free overview - quick domain health check with basic DNS',
  input: z.object({ domain: z.string().describe('Domain to check (e.g., google.com)') }),
  price: { amount: 0 },
  handler: async (ctx) => {
    const domain = extractDomain(ctx.input.domain);
    
    // Get basic A record
    const dns = await fetchJSON(`https://dns.google/resolve?name=${domain}&type=A`);
    
    return {
      output: {
        domain,
        status: dns.Status === 0 ? 'active' : 'error',
        hasARecords: Boolean(dns.Answer?.length),
        recordCount: dns.Answer?.length || 0,
        fetchedAt: new Date().toISOString(),
        dataSource: 'Google DNS (live)'
      }
    };
  },
});

// === PAID ENDPOINT 1 ($0.001) - DNS Records ===
addEntrypoint({
  key: 'dns',
  description: 'Full DNS records - A, AAAA, MX, NS, TXT, CNAME',
  input: z.object({ 
    domain: z.string().describe('Domain to lookup'),
    types: z.array(z.enum(['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'])).optional().default(['A', 'AAAA', 'MX', 'NS', 'TXT'])
  }),
  price: { amount: 1000 }, // $0.001
  handler: async (ctx) => {
    const domain = extractDomain(ctx.input.domain);
    const types = ctx.input.types;
    
    // Fetch all record types in parallel
    const results = await Promise.all(
      types.map(async (type) => {
        try {
          const data = await fetchJSON(`https://dns.google/resolve?name=${domain}&type=${type}`);
          return {
            type,
            records: data.Answer?.map((r: any) => ({
              name: r.name,
              data: r.data,
              ttl: r.TTL
            })) || [],
            status: data.Status === 0 ? 'ok' : 'error'
          };
        } catch (e: any) {
          return { type, records: [], status: 'error', error: e.message };
        }
      })
    );
    
    return {
      output: {
        domain,
        records: results,
        totalRecords: results.reduce((sum, r) => sum + r.records.length, 0),
        fetchedAt: new Date().toISOString()
      }
    };
  },
});

// === PAID ENDPOINT 2 ($0.002) - SSL Certificates ===
addEntrypoint({
  key: 'ssl',
  description: 'SSL certificate transparency data - issued certs, subdomains discovered',
  input: z.object({ 
    domain: z.string().describe('Domain to lookup'),
    limit: z.number().optional().default(20).describe('Max certificates to return')
  }),
  price: { amount: 2000 }, // $0.002
  handler: async (ctx) => {
    const domain = extractDomain(ctx.input.domain);
    const limit = Math.min(ctx.input.limit, 100);
    
    const certs = await fetchJSON(`https://crt.sh/?q=${domain}&output=json`, 15000);
    
    // Process and deduplicate
    const processed = Array.isArray(certs) ? certs.slice(0, limit).map((cert: any) => ({
      id: cert.id,
      commonName: cert.common_name,
      issuer: cert.issuer_name,
      notBefore: cert.not_before,
      notAfter: cert.not_after,
      subdomains: cert.name_value?.split('\n').filter((n: string) => n.includes(domain)) || []
    })) : [];
    
    // Extract unique subdomains
    const allSubdomains = new Set<string>();
    processed.forEach((cert: any) => {
      cert.subdomains.forEach((s: string) => allSubdomains.add(s.replace('*.', '')));
    });
    
    return {
      output: {
        domain,
        certificates: processed,
        uniqueSubdomains: Array.from(allSubdomains).slice(0, 50),
        totalCertificates: Array.isArray(certs) ? certs.length : 0,
        fetchedAt: new Date().toISOString()
      }
    };
  },
});

// === PAID ENDPOINT 3 ($0.002) - IP Geolocation ===
addEntrypoint({
  key: 'geoip',
  description: 'IP geolocation - resolve domain and get location, ISP, timezone',
  input: z.object({ 
    domain: z.string().describe('Domain or IP address to lookup')
  }),
  price: { amount: 2000 }, // $0.002
  handler: async (ctx) => {
    const domain = extractDomain(ctx.input.domain);
    
    // First resolve domain to IP if needed
    let ip = domain;
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
      const dns = await fetchJSON(`https://dns.google/resolve?name=${domain}&type=A`);
      if (dns.Answer?.[0]?.data) {
        ip = dns.Answer[0].data;
      } else {
        throw new Error('Could not resolve domain to IP');
      }
    }
    
    // Get geolocation
    const geo = await fetchJSON(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,hosting`);
    
    if (geo.status !== 'success') {
      throw new Error(geo.message || 'Geolocation lookup failed');
    }
    
    return {
      output: {
        domain,
        ip,
        location: {
          country: geo.country,
          countryCode: geo.countryCode,
          region: geo.regionName,
          city: geo.city,
          zip: geo.zip,
          lat: geo.lat,
          lon: geo.lon,
          timezone: geo.timezone
        },
        network: {
          isp: geo.isp,
          org: geo.org,
          as: geo.as,
          isHosting: geo.hosting
        },
        fetchedAt: new Date().toISOString()
      }
    };
  },
});

// === PAID ENDPOINT 4 ($0.003) - HTTP Headers Analysis ===
addEntrypoint({
  key: 'headers',
  description: 'HTTP headers analysis - security headers, server info, redirects',
  input: z.object({ 
    domain: z.string().describe('Domain to check'),
    followRedirects: z.boolean().optional().default(true)
  }),
  price: { amount: 3000 }, // $0.003
  handler: async (ctx) => {
    const domain = extractDomain(ctx.input.domain);
    const url = `https://${domain}`;
    
    const response = await fetch(url, {
      method: 'HEAD',
      redirect: ctx.input.followRedirects ? 'follow' : 'manual'
    });
    
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    
    // Analyze security headers
    const securityHeaders = {
      strictTransportSecurity: headers['strict-transport-security'] || null,
      contentSecurityPolicy: headers['content-security-policy'] || null,
      xFrameOptions: headers['x-frame-options'] || null,
      xContentTypeOptions: headers['x-content-type-options'] || null,
      xXssProtection: headers['x-xss-protection'] || null,
      referrerPolicy: headers['referrer-policy'] || null,
      permissionsPolicy: headers['permissions-policy'] || null
    };
    
    const securityScore = Object.values(securityHeaders).filter(Boolean).length;
    
    return {
      output: {
        domain,
        url: response.url,
        status: response.status,
        statusText: response.statusText,
        server: headers['server'] || 'unknown',
        poweredBy: headers['x-powered-by'] || null,
        securityHeaders,
        securityScore: `${securityScore}/7`,
        allHeaders: headers,
        fetchedAt: new Date().toISOString()
      }
    };
  },
});

// === PAID ENDPOINT 5 ($0.005) - Full Domain Report ===
addEntrypoint({
  key: 'report',
  description: 'Comprehensive domain report - DNS, SSL, GeoIP, and headers combined',
  input: z.object({ 
    domain: z.string().describe('Domain for full analysis')
  }),
  price: { amount: 5000 }, // $0.005
  handler: async (ctx) => {
    const domain = extractDomain(ctx.input.domain);
    
    // Fetch all data sources in parallel
    const [dnsA, dnsMX, dnsNS, certs, geo] = await Promise.all([
      fetchJSON(`https://dns.google/resolve?name=${domain}&type=A`).catch(() => ({ Answer: [] })),
      fetchJSON(`https://dns.google/resolve?name=${domain}&type=MX`).catch(() => ({ Answer: [] })),
      fetchJSON(`https://dns.google/resolve?name=${domain}&type=NS`).catch(() => ({ Answer: [] })),
      fetchJSON(`https://crt.sh/?q=${domain}&output=json`, 15000).catch(() => []),
      (async () => {
        const dns = await fetchJSON(`https://dns.google/resolve?name=${domain}&type=A`);
        if (dns.Answer?.[0]?.data) {
          return fetchJSON(`http://ip-api.com/json/${dns.Answer[0].data}?fields=status,country,countryCode,city,isp,org,hosting`);
        }
        return null;
      })().catch(() => null)
    ]);
    
    // Try to get headers (may fail for some domains)
    let headers: any = null;
    try {
      const response = await fetch(`https://${domain}`, { method: 'HEAD' });
      headers = {
        status: response.status,
        server: response.headers.get('server'),
        hasHSTS: Boolean(response.headers.get('strict-transport-security'))
      };
    } catch {}
    
    // Extract subdomains from certs
    const subdomains = new Set<string>();
    if (Array.isArray(certs)) {
      certs.slice(0, 50).forEach((cert: any) => {
        cert.name_value?.split('\n').forEach((name: string) => {
          if (name.includes(domain)) subdomains.add(name.replace('*.', ''));
        });
      });
    }
    
    return {
      output: {
        domain,
        summary: {
          hasARecords: Boolean(dnsA.Answer?.length),
          hasMXRecords: Boolean(dnsMX.Answer?.length),
          hasNSRecords: Boolean(dnsNS.Answer?.length),
          sslCertificates: Array.isArray(certs) ? certs.length : 0,
          subdomainsFound: subdomains.size
        },
        dns: {
          aRecords: dnsA.Answer?.map((r: any) => r.data) || [],
          mxRecords: dnsMX.Answer?.map((r: any) => r.data) || [],
          nsRecords: dnsNS.Answer?.map((r: any) => r.data) || []
        },
        location: geo?.status === 'success' ? {
          country: geo.country,
          countryCode: geo.countryCode,
          city: geo.city,
          isp: geo.isp,
          isHosting: geo.hosting
        } : null,
        http: headers,
        subdomains: Array.from(subdomains).slice(0, 30),
        generatedAt: new Date().toISOString()
      }
    };
  },
});

const port = Number(process.env.PORT ?? 3000);
console.log(`Domain Intel Agent running on port ${port}`);

export default { port, fetch: app.fetch };
