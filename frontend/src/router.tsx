import { QueryClient, useQuery } from "@tanstack/react-query";
import {
  createRootRouteWithContext,
  createRoute,
  createRouter,
  Link,
  Outlet,
  redirect,
  type ErrorComponentProps,
} from "@tanstack/react-router";
import { meQueryOptions } from "./auth";
import { errorMessage } from "./components";
import { DashboardPage } from "./pages/Dashboard";
import { HomePage } from "./pages/Home";
import { LoginJwtPage } from "./pages/LoginJwt";
import { LoginMfaPage } from "./pages/LoginMfa";
import { LoginOAuthPage } from "./pages/LoginOAuth";
import { LoginPasswordPage } from "./pages/LoginPassword";
import { RegisterPage } from "./pages/Register";

type RouterContext = { queryClient: QueryClient };

function RootLayout() {
  // Observe the cached identity without fetching it, to show a Dashboard link once signed in.
  const { data: me } = useQuery({ ...meQueryOptions, enabled: false });

  return (
    <div className="app">
      <header className="site-header">
        <div className="container header-inner">
          <Link to="/" className="brand">
            <span className="brand-mark" aria-hidden="true">
              🔐
            </span>
            Auth Patterns Demo
          </Link>
          <nav className="site-nav" aria-label="Main">
            <Link to="/login/password">Password</Link>
            <Link to="/login/oauth">OAuth</Link>
            <Link to="/login/mfa">MFA</Link>
            <Link to="/login/jwt">JWT</Link>
            {me ? <Link to="/dashboard">Dashboard</Link> : <Link to="/register">Register</Link>}
          </nav>
        </div>
      </header>
      <main className="container main">
        <Outlet />
      </main>
    </div>
  );
}

function RouteError({ error, reset }: ErrorComponentProps) {
  return (
    <section className="card narrow">
      <h1>Something went wrong</h1>
      <div className="alert alert-error" role="alert">
        <p>{errorMessage(error)}</p>
      </div>
      <div className="button-row">
        <button type="button" className="btn" onClick={reset}>
          Try again
        </button>
        <Link to="/" className="btn btn-primary">
          Back to home
        </Link>
      </div>
    </section>
  );
}

function NotFound() {
  return (
    <section className="card narrow">
      <h1>Page not found</h1>
      <Link to="/" className="btn btn-primary">
        Back to home
      </Link>
    </section>
  );
}

const rootRoute = createRootRouteWithContext<RouterContext>()({
  component: RootLayout,
  errorComponent: RouteError,
  notFoundComponent: NotFound,
});

const homeRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: HomePage });

const registerRoute = createRoute({ getParentRoute: () => rootRoute, path: "/register", component: RegisterPage });

const loginPasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login/password",
  component: LoginPasswordPage,
});

const loginOAuthRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login/oauth",
  validateSearch: (search: Record<string, unknown>): { error?: string } =>
    typeof search.error === "string" && search.error ? { error: search.error } : {},
  component: LoginOAuthPage,
});

const loginMfaRoute = createRoute({ getParentRoute: () => rootRoute, path: "/login/mfa", component: LoginMfaPage });

const loginJwtRoute = createRoute({ getParentRoute: () => rootRoute, path: "/login/jwt", component: LoginJwtPage });

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/dashboard",
  beforeLoad: async ({ context }) => {
    try {
      await context.queryClient.ensureQueryData(meQueryOptions);
    } catch {
      throw redirect({ to: "/" });
    }
  },
  component: DashboardPage,
});

const routeTree = rootRoute.addChildren([
  homeRoute,
  registerRoute,
  loginPasswordRoute,
  loginOAuthRoute,
  loginMfaRoute,
  loginJwtRoute,
  dashboardRoute,
]);

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false },
  },
});

export const router = createRouter({ routeTree, context: { queryClient }, scrollRestoration: true });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
