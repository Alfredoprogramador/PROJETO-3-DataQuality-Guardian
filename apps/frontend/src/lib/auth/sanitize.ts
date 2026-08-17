/**
 * Camada 7 — DOMPurify input sanitization utility
 * Use sanitize() on any user-supplied HTML before rendering with dangerouslySetInnerHTML.
 */
import type DOMPurify from "dompurify";

// Lazy-loaded client-side only — DOMPurify requires the DOM (window/document)
let _purify: typeof DOMPurify | null = null;

function getPurify(): typeof DOMPurify | null {
  if (typeof window === "undefined") return null;
  if (!_purify) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    _purify = require("dompurify") as typeof DOMPurify;
  }
  return _purify;
}

/**
 * Strip all HTML/XML tags from a string (server-side safe fallback).
 * Applies the replacement in a loop until the string stabilises to handle
 * nested or incomplete tag constructs that a single pass might miss.
 */
function _stripTagsSsr(dirty: string): string {
  let prev = dirty;
  // Replace angle-bracket constructs; repeat until stable
  let result = dirty.replace(/[<>]/g, "");
  while (result !== prev) {
    prev = result;
    result = prev.replace(/[<>]/g, "");
  }
  return result;
}

/**
 * Sanitize HTML string to prevent XSS.
 * Safe to call on both client and server (returns plain text on server).
 */
export function sanitizeHtml(dirty: string): string {
  const purify = getPurify();
  if (!purify) {
    return _stripTagsSsr(dirty);
  }
  return purify.sanitize(dirty, {
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
  const purify = getPurify();
  if (!purify) {
    return _stripTagsSsr(input).trim();
  }
  return purify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }).trim();
}
