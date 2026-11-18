import { NextResponse } from 'next/server';

// Edge Runtime compatible JWT validation
function validateJWT(token) {
  try {
    if (!token || typeof token !== 'string') {
      return { valid: false, error: 'Missing token' };
    }

    // Split the token
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid token format' };
    }

    // Decode the payload
    let payload;
    try {
      payload = JSON.parse(atob(parts[1]));
    } catch (e) {
      return { valid: false, error: 'Invalid token payload' };
    }

    // Check if token is expired
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return { valid: false, error: 'Token expired' };
    }

    // Check if token has required fields
    if (!payload.userId && !payload.adminId) {
      return { valid: false, error: 'Invalid token payload' };
    }

    return { valid: true, payload };
  } catch (error) {
    return { valid: false, error: 'Token validation failed' };
  }
}

export function middleware(request) {
  const { pathname } = request.nextUrl;
  
  // Skip middleware for static files, favicon, and images
  if (
    pathname === '/favicon.ico' || 
    pathname.startsWith('/_next/') || 
    pathname.startsWith('/public/') ||
    pathname.startsWith('/images/') ||
    pathname.startsWith('/uploads/')
  ) {
    return NextResponse.next();
  }

  // Get tokens from cookies and headers
  const userToken = request.cookies.get('auth-token')?.value;
  let adminToken = request.cookies.get('admin-token')?.value;
  
  if (!adminToken) {
    const authHeader = request.headers.get('authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      adminToken = authHeader.substring(7);
    }
  }

  // Validate tokens
  const userValidation = userToken ? validateJWT(userToken) : { valid: false };
  const adminValidation = adminToken ? validateJWT(adminToken) : { valid: false };

  const hasValidUser = Boolean(userValidation.valid && userValidation.payload?.userId);
  const hasValidAdmin = Boolean(adminValidation.valid && adminValidation.payload?.adminId);

  // Route classifications
  const isRoot = pathname === '/';
  const isAdminRoute = pathname.startsWith('/admin');
  const isAdminPublicRoute = pathname === '/admin/login' || pathname.startsWith('/admin/login/');
  const isUserRoute = pathname.startsWith('/user-dashboard');
  const isLegacyDashboard = pathname === '/dashboard' || pathname.startsWith('/dashboard/');
  const publicRoutes = ['/login', '/signup', '/verify-email', '/forgot-password', '/reset-password'];
  const isUserPublicRoute = publicRoutes.some(route => pathname === route || pathname.startsWith(route + '/'));

  // 1. Root route: redirect logged-in users directly to their dashboard
  if (isRoot) {
    if (hasValidUser) {
      return NextResponse.redirect(new URL('/user-dashboard', request.url));
    }
    if (hasValidAdmin) {
      return NextResponse.redirect(new URL('/admin/dashboard', request.url));
    }
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // 2. Legacy /dashboard routes: redirect to proper modern dashboard
  if (isLegacyDashboard) {
    if (hasValidAdmin) {
      return NextResponse.redirect(new URL('/admin/dashboard', request.url));
    }
    if (hasValidUser) {
      return NextResponse.redirect(new URL('/user-dashboard', request.url));
    }
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // 3. Admin routes handling
  if (isAdminRoute) {
    // If accessing admin login with valid admin token, redirect to admin dashboard
    if (isAdminPublicRoute) {
      if (hasValidAdmin) {
        return NextResponse.redirect(new URL('/admin/dashboard', request.url));
      }
      return NextResponse.next();
    }

    // Protected admin routes: require valid admin token
    if (!hasValidAdmin) {
      if (pathname.startsWith('/api/admin/')) {
        return NextResponse.json(
          { error: 'Unauthorized: Admin authentication required' },
          { status: 401 }
        );
      }

      const loginUrl = new URL('/admin/login', request.url);
      loginUrl.searchParams.set('redirect', pathname);
      const response = NextResponse.redirect(loginUrl);
      if (adminToken) {
        response.cookies.delete('admin-token');
      }
      return response;
    }

    // Admin token is valid - inject admin info for API routes
    if (pathname.startsWith('/api/admin/')) {
      const requestHeaders = new Headers(request.headers);
      requestHeaders.set('x-admin-id', String(adminValidation.payload.adminId));
      if (adminValidation.payload.username) requestHeaders.set('x-admin-username', adminValidation.payload.username);
      if (adminValidation.payload.email) requestHeaders.set('x-admin-email', adminValidation.payload.email);
      requestHeaders.set('x-admin-role', adminValidation.payload.role || 'admin');

      return NextResponse.next({
        request: {
          headers: requestHeaders,
        },
      });
    }

    return NextResponse.next();
  }

  // 4. Public user routes (login, signup, etc.)
  if (isUserPublicRoute) {
    // If user already has a valid session, redirect to user dashboard
    if (hasValidUser) {
      return NextResponse.redirect(new URL('/user-dashboard', request.url));
    }
    // If admin arrives at user login without user session, redirect to admin dashboard
    if (hasValidAdmin && !userToken) {
      return NextResponse.redirect(new URL('/admin/dashboard', request.url));
    }
    return NextResponse.next();
  }

  // 5. User protected routes (/user-dashboard/*)
  if (isUserRoute) {
    if (!hasValidUser) {
      const loginUrl = new URL('/login', request.url);
      loginUrl.searchParams.set('redirect', pathname);
      const response = NextResponse.redirect(loginUrl);
      if (userToken) {
        response.cookies.delete('auth-token');
      }
      return response;
    }

    return NextResponse.next();
  }

  // 6. User API routes: inject user headers if authenticated
  if (pathname.startsWith('/api/') && !pathname.startsWith('/api/admin/')) {
    if (hasValidUser) {
      const requestHeaders = new Headers(request.headers);
      requestHeaders.set('x-user-id', String(userValidation.payload.userId));
      if (userValidation.payload.email) requestHeaders.set('x-user-email', userValidation.payload.email);
      requestHeaders.set('x-user-role', userValidation.payload.role || 'user');

      return NextResponse.next({
        request: {
          headers: requestHeaders,
        },
      });
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|public/|images/|uploads/).*)',
  ],
};
