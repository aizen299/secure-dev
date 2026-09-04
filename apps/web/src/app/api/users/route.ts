import { NextResponse } from "next/server";
import { hasSession } from "@/lib/guard";
import { createUser, listUsers, ApiError } from "@/lib/api";

/**
 * The roster, and creating an account.
 *
 * Both forward to the API, which decides whether this session may. The
 * dashboard does NOT check the role itself: a second copy of that rule would be
 * a place for the two to disagree, and the weaker one would decide. What the
 * API refuses with a 403 reaches the page as a 403.
 */
export async function GET() {
  if (!(await hasSession())) {
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }
  try {
    return NextResponse.json(await listUsers());
  } catch (error) {
    return forward(error);
  }
}

export async function POST(request: Request) {
  if (!(await hasSession())) {
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  const body = (await request.json().catch(() => null)) as {
    email?: string;
    password?: string;
    display_name?: string;
    role?: "viewer" | "engineer" | "admin";
  } | null;

  if (!body?.email || !body?.password) {
    return NextResponse.json({ error: "An email and a password are required." }, { status: 400 });
  }

  try {
    return NextResponse.json(
      await createUser({
        email: body.email,
        password: body.password,
        display_name: body.display_name,
        role: body.role,
      }),
      { status: 201 },
    );
  } catch (error) {
    return forward(error);
  }
}

/**
 * Passes the API's own message through.
 *
 * "password must be at least 12 characters" and "an account already exists for
 * that email" are exactly what the person filling the form needs, and the API
 * writes them to be client-safe — they name the rule broken and never echo the
 * value.
 */
function forward(error: unknown) {
  if (error instanceof ApiError) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }
  return NextResponse.json({ error: "The API is unreachable." }, { status: 502 });
}
