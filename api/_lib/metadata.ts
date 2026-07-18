// Minimal Salesforce Metadata API (SOAP) client for reading org-wide settings
// that Health Check and SOQL do not expose (session/security/file-upload/etc.).
// Uses readMetadata with the OAuth access token as the SOAP session id.

import { XMLParser } from "fast-xml-parser";

const API_VERSION = "60.0";

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
