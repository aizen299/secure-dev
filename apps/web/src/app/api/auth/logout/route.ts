import { NextResponse } from "next/server";
import { SESSION_COOKIE } from "@/lib/session-cookie";

export async function POST(request: Request) {
  const response = NextResponse.redirect(new URL("/login", request.url), 303);
  response.cookies.set(SESSION_COOKIE, "", { path: "/", maxAge: 0 });
  return response;
}
