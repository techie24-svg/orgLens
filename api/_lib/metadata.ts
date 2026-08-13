// Minimal Salesforce Metadata API (SOAP) client for reading org-wide settings
// that Health Check and SOQL do not expose (session/security/file-upload/etc.).
// Uses readMetadata with the OAuth access token as the SOAP session id.

import { XMLParser } from "fast-xml-parser";

const API_VERSION = "64.0";

const parser = new XMLParser({
  ignoreAttributes: true,
  removeNSPrefix: true,
  parseTagValue: false, // keep values as strings; callers coerce explicitly
});

function esc(s: string): string {
  return s.replace(/[<>&'"]/g, (c) => (
    { "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c] as string
  ));
}

/**
 * readMetadata(type, fullName) → the parsed `records` object for that settings
 * type, or null on any failure (caller degrades the affected checks to
 * "Not Evaluated"). Never throws.
 */
export async function readMetadata(
  instanceUrl: string,
  token: string,
  type: string,
  fullName: string
): Promise<Record<string, any> | null> {
  const envelope =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ` +
    `xmlns:met="http://soap.sforce.com/2006/04/metadata">` +
    `<soapenv:Header><met:SessionHeader><met:sessionId>${esc(token)}</met:sessionId>` +
    `</met:SessionHeader></soapenv:Header>` +
    `<soapenv:Body><met:readMetadata><met:type>${esc(type)}</met:type>` +
    `<met:fullNames>${esc(fullName)}</met:fullNames></met:readMetadata></soapenv:Body>` +
    `</soapenv:Envelope>`;

  const res = await fetch(`${instanceUrl}/services/Soap/m/${API_VERSION}`, {
    method: "POST",
    headers: { "Content-Type": "text/xml; charset=UTF-8", SOAPAction: '""' },
    body: envelope,
  });
  const text = await res.text();
  if (!res.ok) {
    // Surface a compact SOAP fault message for diagnostics.
    const fault = /<faultstring>([\s\S]*?)<\/faultstring>/.exec(text)?.[1];
    throw new Error(`Metadata ${res.status} ${type}: ${(fault ?? text).slice(0, 200)}`);
  }
  const parsed = parser.parse(text);
  const result = parsed?.Envelope?.Body?.readMetadataResponse?.result;
  const records = result?.records ?? result;
  return records && typeof records === "object" ? (records as Record<string, any>) : null;
}

function soapCall(instanceUrl: string, token: string, bodyInner: string): Promise<string> {
  const envelope =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ` +
    `xmlns:met="http://soap.sforce.com/2006/04/metadata">` +
    `<soapenv:Header><met:SessionHeader><met:sessionId>${esc(token)}</met:sessionId>` +
    `</met:SessionHeader></soapenv:Header>` +
    `<soapenv:Body>${bodyInner}</soapenv:Body></soapenv:Envelope>`;
  return fetch(`${instanceUrl}/services/Soap/m/${API_VERSION}`, {
    method: "POST",
    headers: { "Content-Type": "text/xml; charset=UTF-8", SOAPAction: '""' },
    body: envelope,
  }).then(async (res) => {
    const text = await res.text();
    if (!res.ok) {
      const fault = /<faultstring>([\s\S]*?)<\/faultstring>/.exec(text)?.[1];
      throw new Error(`Metadata ${res.status}: ${(fault ?? text).slice(0, 200)}`);
    }
    return text;
  });
}

function asArray<T>(v: T | T[] | undefined | null): T[] {
  return v === undefined || v === null ? [] : Array.isArray(v) ? v : [v];
}

/** listMetadata(type) → the component fullNames of that metadata type. */
export async function listMetadata(instanceUrl: string, token: string, type: string): Promise<string[]> {
  const text = await soapCall(
    instanceUrl,
    token,
    `<met:listMetadata><met:queries><met:type>${esc(type)}</met:type></met:queries>` +
    `<met:asOfVersion>${API_VERSION}</met:asOfVersion></met:listMetadata>`
  );
  const parsed = parser.parse(text);
  const results = asArray(parsed?.Envelope?.Body?.listMetadataResponse?.result);
  return results.map((r: any) => r?.fullName).filter(Boolean);
}

/** readMetadata for up to 10 fullNames at once → the parsed records array. */
export async function readMetadataMany(
  instanceUrl: string,
  token: string,
  type: string,
  fullNames: string[]
): Promise<Record<string, any>[]> {
  if (!fullNames.length) return [];
  const names = fullNames.slice(0, 10).map((n) => `<met:fullNames>${esc(n)}</met:fullNames>`).join("");
  const text = await soapCall(
    instanceUrl,
    token,
    `<met:readMetadata><met:type>${esc(type)}</met:type>${names}</met:readMetadata>`
  );
  const parsed = parser.parse(text);
  return asArray(parsed?.Envelope?.Body?.readMetadataResponse?.result?.records) as Record<string, any>[];
}

/**
 * readMetadata across any number of fullNames by batching into the API's
 * 10-per-call limit. Batches run sequentially to stay well inside org API limits;
 * `cap` bounds the total read so a huge org cannot stall a scan.
 */
export async function readMetadataAll(
  instanceUrl: string,
  token: string,
  type: string,
  fullNames: string[],
  cap = 200
): Promise<Record<string, any>[]> {
  const names = fullNames.slice(0, cap);
  const out: Record<string, any>[] = [];
  for (let i = 0; i < names.length; i += 10) {
    out.push(...(await readMetadataMany(instanceUrl, token, type, names.slice(i, i + 10))));
  }
  return out;
}

/** Flatten a nested settings object into dotted paths (arrays are indexed). */
export function flatten(obj: any, prefix = "", out: Record<string, string> = {}): Record<string, string> {
  if (obj === null || obj === undefined) return out;
  if (typeof obj !== "object") { out[prefix] = String(obj); return out; }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => flatten(v, `${prefix}[${i}]`, out));
    return out;
  }
  for (const [k, v] of Object.entries(obj)) {
    flatten(v, prefix ? `${prefix}.${k}` : k, out);
  }
  return out;
}
