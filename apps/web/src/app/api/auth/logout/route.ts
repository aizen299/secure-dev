import { SESSION_COOKIE } from "@/lib/session-cookie";
import { redirectTo } from "@/lib/redirect";

export async function POST() {
  const response = redirectTo("/login");
  response.cookies.set(SESSION_COOKIE, "", { path: "/", maxAge: 0 });
  return response;
}
