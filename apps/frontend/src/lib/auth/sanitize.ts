/**
 * Camada 7 — DOMPurify input sanitization utility
 * Use sanitize() on any user-supplied HTML before rendering with dangerouslySetInnerHTML.
 */

/**
 * Sanitize HTML string to prevent XSS.
 * Safe to call on both client and server (returns plain text on server).
 */
export function sanitizeHtml(dirty: string): string {
  if (typeof window === "undefined") {
    // Server-side: strip all HTML tags as a safe fallback
    return dirty.replace(/<[^>]*>/g, "");
  }
  // Client-side: use DOMPurify
  const DOMPurify = require("dompurify");
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "ul", "ol", "li", "p", "br"],
    ALLOWED_ATTR: ["href", "target", "rel"],
    FORCE_BODY: true,
  });
}

/**
 * Sanitize a plain text string (no HTML allowed).
 * Use for all form inputs before sending to the API.
 */
export function sanitizeText(input: string): string {
  if (typeof window === "undefined") {
    return input.replace(/<[^>]*>/g, "").trim();
  }
  const DOMPurify = require("dompurify");
  return DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }).trim();
}
