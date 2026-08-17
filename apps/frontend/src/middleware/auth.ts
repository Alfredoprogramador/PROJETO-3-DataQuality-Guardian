/**
 * Camada 7 — Next.js route protection middleware
 * Verifies session on every request to protected routes.
 * Redirects unauthenticated users to /auth/signin.
 * Checks role-based access for admin and steward routes.
 */
import { getToken } from "next-auth/jwt";
import { NextRequest, NextResponse } from "next/server";

// Routes that require authentication
const PROTECTED_PREFIXES = ["/dashboard", "/datasets", "/catalog", "/compliance", "/admin"];
// Routes that require admin role
const ADMIN_PREFIXES = ["/admin"];
// Routes that require at least data_steward
const STEWARD_PREFIXES = ["/compliance"];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  const isProtected = PROTECTED_PREFIXES.some((prefix) => pathname.startsWith(prefix));
  if (!isProtected) {
    return NextResponse.next();
  }

  const token = await getToken({
    req: request,
    secret: process.env.NEXTAUTH_SECRET,
  });

  if (!token) {
    const signInUrl = new URL("/auth/signin", request.url);
    signInUrl.searchParams.set("callbackUrl", request.url);
    return NextResponse.redirect(signInUrl);
  }

  const role = (token.role as string) || "viewer";

  // Admin routes
  if (ADMIN_PREFIXES.some((p) => pathname.startsWith(p)) && role !== "admin") {
    return NextResponse.redirect(new URL("/403", request.url));
  }

  // Steward routes
  if (
    STEWARD_PREFIXES.some((p) => pathname.startsWith(p)) &&
    !["admin", "data_steward"].includes(role)
  ) {
    return NextResponse.redirect(new URL("/403", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|auth).*)"],
};
