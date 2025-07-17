# Secure Coding Prompt: Next.js

## Purpose

This prompt helps you implement secure coding practices in Next.js applications. Use this to generate code that follows security best practices specific to Next.js, addressing both client-side and server-side security concerns.

## Next.js Security Prompt

```
As a secure Next.js developer, help me implement [FEATURE/FUNCTIONALITY] with security as a priority.

Consider these security aspects in your implementation:
1. Protection against common web vulnerabilities (XSS, CSRF, injection)
2. Secure routing and middleware implementation
3. Safe data fetching and API route security
4. Authentication and authorization best practices
5. Secure form handling and input validation
6. Content Security Policy (CSP) implementation
7. Protection against common Next.js specific vulnerabilities
8. Secure state management
9. Safe use of third-party libraries and APIs
10. Security headers configuration

Technical requirements:
- Next.js version: [VERSION]
- Authentication method: [JWT, NextAuth.js, Auth0, etc.]
- Data fetching: [SWR, React Query, built-in Next.js methods, etc.]
- Deployment target: [Vercel, self-hosted, etc.]
- SSR/SSG requirements: [Server-side rendering, Static Site Generation, ISR, etc.]

Follow these Next.js security best practices:
- Implement proper input validation on both client and server
- Configure security headers with next.config.js
- Use getServerSideProps/getStaticProps securely
- Implement proper authentication checks in API routes
- Follow secure coding patterns specific to React and Next.js
- Use ESLint with security plugins
```

## Security Considerations for Next.js

### Authentication & Authorization

- **NextAuth.js Security**: Proper configuration, session handling, CSRF protection
- **JWT Security**: Secure signing, proper storage, refresh token rotation
- **Session Management**: Secure cookie settings, proper expiration, session validation
- **OAuth Implementation**: Secure callback handling, state parameter, PKCE

### Server-Side Rendering Security

- **Data Fetching**: Secure access to backends, API authentication, preventing data leaks
- **Context Isolation**: Separating client/server contexts securely
- **Server Component Security**: Proper use of React Server Components
- **Authentication in SSR**: Secure session validation in getServerSideProps

### API Routes Security

- **Input Validation**: Thorough request validation
- **Authentication**: Proper auth checks in API handlers
- **Rate Limiting**: Preventing abuse of API routes
- **CORS Configuration**: Proper origins restriction

### Client-Side Security

- **React Security**: Preventing XSS, secure state management
- **Form Handling**: CSRF protection, input validation
- **State Management**: Secure client-side state handling
- **Safe DOM Manipulation**: Preventing client-side injection attacks

### Security Headers

- **CSP Configuration**: Content Security Policy setup in Next.js
- **CORS Headers**: Proper cross-origin configuration
- **Cache Controls**: Preventing sensitive data caching
- **Frame Protection**: Clickjacking prevention

### Environment Variables

- **Secure Env Vars**: Proper use of server-side vs client-side variables
- **Secrets Management**: Keeping secrets out of client bundles
- **Validation**: Validating environment setup

## Example Implementations

### Secure Next.js Configuration

```javascript
// next.config.js
const ContentSecurityPolicy = `
  default-src 'self';
  script-src 'self' 'unsafe-eval' 'unsafe-inline' https://trusted-cdn.com;
  style-src 'self' 'unsafe-inline' https://trusted-cdn.com;
  img-src 'self' data: https://trusted-cdn.com;
  font-src 'self' https://trusted-cdn.com;
  connect-src 'self' https://api.yourdomain.com;
  frame-src 'none';
  object-src 'none';
`;

const securityHeaders = [
  // CSP Header
  {
    key: 'Content-Security-Policy',
    value: ContentSecurityPolicy.replace(/\s{2,}/g, ' ').trim()
  },
  // XSS Protection
  {
    key: 'X-XSS-Protection',
    value: '1; mode=block'
  },
  // Prevent iframe embedding (clickjacking)
  {
    key: 'X-Frame-Options',
    value: 'DENY'
  },
  // Prevent MIME type sniffing
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff'
  },
  // Referrer Policy
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin'
  },
  // Permissions Policy
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=()'
  },
  // HSTS
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload'
  }
];

module.exports = {
  reactStrictMode: true,
  async headers() {
    return [
      {
        // Apply these headers to all routes
        source: '/:path*',
        headers: securityHeaders,
      },
    ];
  },
  // Prevent sensitive env vars from leaking to client
  env: {
    // Only include client-safe env vars here
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL
  }
};
```

### Secure API Route

```typescript
// pages/api/users/[id].ts
import { NextApiRequest, NextApiResponse } from 'next';
import { getSession } from 'next-auth/react';
import { z } from 'zod';

// Input validation schema
const userUpdateSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: z.string().email().optional(),
  // No sensitive fields like role allowed
});

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  // 1. Session validation
  const session = await getSession({ req });
  
  if (!session || !session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  // 2. Method validation
  if (req.method !== 'PUT') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  
  // 3. Extract and validate parameters
  const { id } = req.query;
  
  if (typeof id !== 'string') {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  
  // 4. Authorization check - users can only modify their own data
  // unless they're an admin
  const isOwnProfile = session.user.id === id;
  const isAdmin = session.user.role === 'admin';
  
  if (!isOwnProfile && !isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  // 5. Input validation
  try {
    const validatedData = userUpdateSchema.parse(req.body);
    
    // 6. Perform database operation securely
    // Use parameterized queries or ORM to prevent injection
    const updatedUser = await prisma.user.update({
      where: { id },
      data: validatedData,
      // 7. Select only safe fields to return
      select: {
        id: true,
        name: true,
        email: true,
        // Don't include sensitive data
      }
    });
    
    // 8. Return sanitized response
    return res.status(200).json(updatedUser);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ 
        error: 'Validation error',
        details: error.errors
      });
    }
    
    // 9. Secure error handling - don't leak implementation details
    console.error('Error updating user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
```

### Secure Server-Side Rendering

```typescript
// pages/dashboard.tsx
import { GetServerSideProps, NextPage } from 'next';
import { getSession } from 'next-auth/react';
import { DashboardLayout } from '@/components/layouts';
import { sanitizeUserData } from '@/utils/security';

interface DashboardProps {
  user: UserData;
  dashboardData: DashboardData;
}

export const getServerSideProps: GetServerSideProps = async (context) => {
  // 1. Session validation
  const session = await getSession(context);
  
  // 2. Authentication check
  if (!session || !session.user) {
    return {
      redirect: {
        destination: '/login?returnUrl=/dashboard',
        permanent: false,
      },
    };
  }
  
  try {
    // 3. Secure data fetching with proper authentication
    const dashboardResponse = await fetch(
      `${process.env.INTERNAL_API_URL}/dashboard`,
      {
        headers: {
          // Use server-side auth token, not exposed to client
          Authorization: `Bearer ${process.env.API_SECRET_TOKEN}`,
          'User-Id': session.user.id, // Pass user context securely
        },
      }
    );
    
    if (!dashboardResponse.ok) {
      throw new Error('Failed to fetch dashboard data');
    }
    
    const dashboardData = await dashboardResponse.json();
    
    // 4. Only return necessary data to client, sanitize sensitive info
    return {
      props: {
        // Only include public user data
        user: sanitizeUserData(session.user),
        // Sanitize dashboard data before sending to client
        dashboardData: sanitizeDashboardData(dashboardData),
      },
    };
  } catch (error) {
    // 5. Handle errors securely without exposing details
    console.error('Dashboard data fetch error:', error);
    
    return {
      props: {
        user: sanitizeUserData(session.user),
        dashboardData: null,
        error: 'Failed to load dashboard data',
      },
    };
  }
};

const Dashboard: NextPage<DashboardProps> = ({ user, dashboardData }) => {
  // Rest of component
};

export default Dashboard;
```

### Secure Form Handling

```tsx
// components/ContactForm.tsx
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { DOMPurify } from 'isomorphic-dompurify';

// Input validation schema
const contactSchema = z.object({
  name: z.string().min(2).max(50),
  email: z.string().email(),
  message: z.string().min(10).max(1000),
});

type ContactFormData = z.infer<typeof contactSchema>;

export default function ContactForm() {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitResult, setSubmitResult] = useState<{
    success?: string;
    error?: string;
  }>({});
  
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ContactFormData>({
    resolver: zodResolver(contactSchema),
  });
  
  const onSubmit = async (data: ContactFormData) => {
    try {
      setIsSubmitting(true);
      
      // Sanitize input data as an extra precaution
      const sanitizedData = {
        name: DOMPurify.sanitize(data.name),
        email: DOMPurify.sanitize(data.email),
        message: DOMPurify.sanitize(data.message),
      };
      
      // Use CSRF protection token from Next.js
      const csrfToken = await getCsrfToken();
      
      const response = await fetch('/api/contact', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          // Include CSRF token in header
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify(sanitizedData),
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Failed to submit form');
      }
      
      // Clear form on success
      reset();
      setSubmitResult({ success: 'Message sent successfully!' });
    } catch (error) {
      // Safe error handling - don't expose implementation details
      console.error('Contact form error:', error);
      setSubmitResult({
        error: 'Failed to send message. Please try again later.',
      });
    } finally {
      setIsSubmitting(false);
    }
  };
  
  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      {/* Use native HTML validation as first line of defense */}
      <div>
        <label htmlFor="name">Name</label>
        <input
          id="name"
          type="text"
          {...register('name')}
          aria-invalid={errors.name ? 'true' : 'false'}
        />
        {errors.name && (
          <span role="alert">{errors.name.message}</span>
        )}
      </div>
      
      <div>
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email" // Use proper input type
          {...register('email')}
          aria-invalid={errors.email ? 'true' : 'false'}
        />
        {errors.email && (
          <span role="alert">{errors.email.message}</span>
        )}
      </div>
      
      <div>
        <label htmlFor="message">Message</label>
        <textarea
          id="message"
          {...register('message')}
          aria-invalid={errors.message ? 'true' : 'false'}
        />
        {errors.message && (
          <span role="alert">{errors.message.message}</span>
        )}
      </div>
      
      {/* Show success/error messages */}
      {submitResult.success && (
        <div className="success">{submitResult.success}</div>
      )}
      {submitResult.error && (
        <div className="error">{submitResult.error}</div>
      )}
      
      {/* Disable button when submitting to prevent multiple submissions */}
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Sending...' : 'Send Message'}
      </button>
    </form>
  );
}
```

### NextAuth.js Secure Configuration

```typescript
// pages/api/auth/[...nextauth].ts
import NextAuth, { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { prisma } from "@/lib/prisma";
import { compare } from "bcryptjs";

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  // Use a strong, randomly generated secret
  secret: process.env.NEXTAUTH_SECRET,
  session: {
    // Use JWT strategy for stateless auth
    strategy: "jwt",
    // Short session lifetime for security
    maxAge: 60 * 60, // 1 hour
  },
  // Security-focused JWT configuration
  jwt: {
    // Short token lifetime
    maxAge: 60 * 60, // 1 hour
  },
  pages: {
    // Custom error page that doesn't leak information
    error: '/auth/error',
    // Custom sign in page with proper validation
    signIn: '/auth/signin',
  },
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      // Specify exact authorization scopes
      authorization: {
        params: {
          scope: "openid email profile",
          prompt: "consent",
        }
      }
    }),
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        // Input validation
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Missing credentials");
        }
        
        // Rate limiting would be implemented here or in middleware
        
        // Secure user lookup - case insensitive email search
        const user = await prisma.user.findUnique({
          where: { email: credentials.email.toLowerCase() },
        });
        
        // Constant time comparison to prevent timing attacks
        if (!user || !(await compare(credentials.password, user.password))) {
          // Generic error to prevent user enumeration
          throw new Error("Invalid credentials");
        }
        
        // Check account status
        if (user.lockedOut || !user.emailVerified) {
          throw new Error("Account is locked or email not verified");
        }
        
        // Only return necessary user data, never the password
        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        };
      }
    })
  ],
  callbacks: {
    // Customize JWT contents
    async jwt({ token, user, account }) {
      // Include minimal user data in token
      if (user) {
        token.userId = user.id;
        token.role = user.role;
      }
      
      // Include auth provider info
      if (account) {
        token.provider = account.provider;
      }
      
      return token;
    },
    // Customize session object
    async session({ session, token }) {
      if (token) {
        // Pass minimal user data to client
        session.user.id = token.userId as string;
        session.user.role = token.role as string;
      }
      return session;
    },
    // Additional security checks
    async redirect({ url, baseUrl }) {
      // Prevent open redirects
      if (url.startsWith(baseUrl)) {
        return url;
      } else if (url.startsWith('/')) {
        // Allow relative URLs
        return new URL(url, baseUrl).toString();
      }
      // Default fallback to base URL
      return baseUrl;
    }
  },
  // Enable debug messages in development only
  debug: process.env.NODE_ENV === "development",
};

export default NextAuth(authOptions);
```

## Security Testing Guidance

When implementing Next.js security features, validate with:

1. **Static Analysis**: Use ESLint with security plugins like `eslint-plugin-security` and `eslint-plugin-react-security`
2. **Security Headers**: Test with https://securityheaders.com
3. **CSP Validation**: Use Google CSP Evaluator
4. **Next.js Specific**: Validate environment variables aren't leaking to client
5. **API Testing**: Use tools like Postman or OWASP ZAP to test API routes
6. **Authentication Testing**: Verify session security, token handling
7. **Authorization Testing**: Check access control enforcement
8. **XSS Testing**: Validate output encoding and CSP effectiveness

## Additional Resources

- [Next.js Security Documentation](https://nextjs.org/docs/advanced-features/security-headers)
- [OWASP React Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/React_Security_Cheat_Sheet.html)
- [NextAuth.js Security Best Practices](https://next-auth.js.org/configuration/options)
- [Web Security Headers in Next.js](https://blog.logrocket.com/web-security-headers-next-js/)
