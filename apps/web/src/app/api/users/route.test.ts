/**
 * @vitest-environment node
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The dashboard's account management (ADR 033, change C).
 *
 * What these tests pin down is that the dashboard FORWARDS rather than decides.
 * A second copy of "only an admin may do this" living here would be a place for
 * the two to disagree, and the weaker one would win -- so the assertions are
 * that a refusal arrives intact and that no request runs before the session
 * gate.
 */

const listUsers = vi.fn();
const createUser = vi.fn();
const updateUser = vi.fn();
const hasSession = vi.fn();

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

vi.mock("@/lib/api", () => ({
  listUsers: (...args: unknown[]) => listUsers(...args),
  createUser: (...args: unknown[]) => createUser(...args),
  updateUser: (...args: unknown[]) => updateUser(...args),
  ApiError,
}));

vi.mock("@/lib/guard", () => ({
  hasSession: () => hasSession(),
}));

async function get() {
  const { GET } = await import("./route");
  return GET();
}

async function post(body: unknown) {
  const { POST } = await import("./route");
  return POST(
    new Request("http://dashboard.test/api/users", { method: "POST", body: JSON.stringify(body) }),
  );
}

async function patch(id: string, body: unknown) {
  const { PATCH } = await import("./[userId]/route");
  return PATCH(
    new Request(`http://dashboard.test/api/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ userId: id }) },
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  hasSession.mockResolvedValue(true);
  listUsers.mockResolvedValue({ data: [] });
  createUser.mockResolvedValue({ id: "user-1" });
  updateUser.mockResolvedValue({ id: "user-1" });
});

describe("the session gate", () => {
  it("refuses the roster without a session, and reads nothing", async () => {
    hasSession.mockResolvedValue(false);

    const response = await get();

    expect(response.status).toBe(401);
    // The roster carries every operator's email. Reading it and then declining
    // to return it would still have sent it over the wire.
    expect(listUsers).not.toHaveBeenCalled();
  });

  it("refuses account creation without a session", async () => {
    hasSession.mockResolvedValue(false);

    const response = await post({ email: "a@example.com", password: "correct horse battery" });

    expect(response.status).toBe(401);
    expect(createUser).not.toHaveBeenCalled();
  });

  it("refuses a change without a session", async () => {
    hasSession.mockResolvedValue(false);

    const response = await patch("user-1", { role: "admin" });

    expect(response.status).toBe(401);
    expect(updateUser).not.toHaveBeenCalled();
  });
});

describe("forwarding the API's answer", () => {
  /**
   * The one that would let the dashboard lie about authorisation.
   *
   * The API refuses the roster to anyone who is not an admin. If that 403 were
   * flattened into a 500 or a 200 with an empty list, the page would report an
   * outage or an empty estate -- both of which read as "nothing to see" rather
   * than "you may not see it".
   */
  it("keeps a 403 a 403", async () => {
    listUsers.mockRejectedValue(new ApiError(403, "forbidden"));

    const response = await get();

    expect(response.status).toBe(403);
  });

  it("keeps the last-administrator refusal a 409, with its reason", async () => {
    updateUser.mockRejectedValue(
      new ApiError(409, "this would leave no enabled administrator; appoint another one first"),
    );

    const response = await patch("user-1", { disabled: true });
    const body = (await response.json()) as { error: string };

    expect(response.status).toBe(409);
    // The message is the whole value of the refusal: it says what to do about
    // it. Replacing it with "the change was not accepted" would leave an admin
    // guessing at a guard that has a specific remedy.
    expect(body.error).toContain("appoint another one first");
  });

  it("keeps the password rule readable", async () => {
    createUser.mockRejectedValue(new ApiError(400, "password must be at least 12 characters"));

    const response = await post({ email: "a@example.com", password: "short" });
    const body = (await response.json()) as { error: string };

    expect(response.status).toBe(400);
    expect(body.error).toBe("password must be at least 12 characters");
  });

  it("reports an unreachable API as a gateway failure, not as a refusal", async () => {
    listUsers.mockRejectedValue(new TypeError("fetch failed"));

    const response = await get();

    // 502, not 403: "the API did not answer" and "the API said no" are
    // different facts, and the page renders them differently.
    expect(response.status).toBe(502);
  });
});

describe("what reaches the API", () => {
  it("sends only the fields the caller asked to change", async () => {
    await patch("user-1", { role: "engineer" });

    // Not `{role, disabled: undefined, projects: undefined}`. The API treats an
    // absent field as "leave it alone", and a request that also carried
    // `disabled` and `projects` would enable a suspended account and revoke
    // every grant -- silently, in the direction of more access.
    expect(updateUser).toHaveBeenCalledWith("user-1", { role: "engineer" });
  });

  it("refuses a change that names nothing", async () => {
    const response = await patch("user-1", {});

    expect(response.status).toBe(400);
    expect(updateUser).not.toHaveBeenCalled();
  });

  it("requires an email and a password before calling the API", async () => {
    const response = await post({ email: "a@example.com" });

    expect(response.status).toBe(400);
    expect(createUser).not.toHaveBeenCalled();
  });

  /**
   * The role is NOT validated here, deliberately.
   *
   * The API owns the list of roles a person may hold -- `service` is a machine
   * role and is excluded there (ADR 033). A copy of that list in the dashboard
   * would be a second place to update, and the stale one would decide.
   */
  it("passes an unknown role through for the API to reject", async () => {
    createUser.mockRejectedValue(new ApiError(400, "role must be one of viewer, engineer, admin"));

    const response = await post({
      email: "a@example.com",
      password: "correct horse battery staple",
      role: "service",
    });

    expect(response.status).toBe(400);
    expect(createUser).toHaveBeenCalled();
  });
});
