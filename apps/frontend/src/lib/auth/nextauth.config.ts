/**
 * Camada 7 — NextAuth OIDC configuration (Keycloak provider)
 * Supports: Keycloak, Azure AD, Google — all via OIDC
 */
import NextAuth, { NextAuthOptions, Session } from "next-auth";
import KeycloakProvider from "next-auth/providers/keycloak";
import { JWT } from "next-auth/jwt";

export const authOptions: NextAuthOptions = {
  providers: [
    KeycloakProvider({
      clientId: process.env.KEYCLOAK_CLIENT_ID!,
      clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!,
      issuer: process.env.KEYCLOAK_ISSUER!,
      // Request offline_access for refresh tokens
      authorization: {
        params: { scope: "openid email profile offline_access" },
      },
    }),
  ],

  session: {
    strategy: "jwt",
    maxAge: 15 * 60,        // 15 minutes — matches backend access token TTL
  },

  callbacks: {
    async jwt({ token, account, profile }): Promise<JWT> {
      // Persist role from Keycloak realm_access claim
      if (account) {
        token.accessToken = account.access_token;
        token.refreshToken = account.refresh_token;
        token.idToken = account.id_token;
      }
      if (profile) {
        const realmAccess = (profile as Record<string, unknown>).realm_access as
          | { roles?: string[] }
          | undefined;
        const roles = realmAccess?.roles ?? [];
        // Map Keycloak roles to our internal role hierarchy
        if (roles.includes("admin")) token.role = "admin";
        else if (roles.includes("data_steward")) token.role = "data_steward";
        else if (roles.includes("analyst")) token.role = "analyst";
        else token.role = "viewer";
      }
      return token;
    },

    async session({ session, token }): Promise<Session> {
      (session as Session & { role?: string; accessToken?: string }).role = token.role as string;
      (session as Session & { role?: string; accessToken?: string }).accessToken =
        token.accessToken as string;
      return session;
    },
  },

  pages: {
    signIn: "/auth/signin",
    error: "/auth/error",
  },

  // Secure cookie settings
  cookies: {
    sessionToken: {
      name: `__Secure-next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: true,
      },
    },
  },
};

export default NextAuth(authOptions);
