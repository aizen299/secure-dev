/**
 * @vitest-environment node
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The dashboard's scan submission (ADR 032).
 *
 * The assertions that matter here are about ORDER, not about outcome. A test
 * that only checked "a refused target returns 400" passed against the broken
 * version too -- it did return 400, having already created a project named
 * after the target it then refused.
 */

const validateTarget = vi.fn();
const createProject = vi.fn();
const createScan = vi.fn();
const listProjects = vi.fn();
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
  validateTarget: (...args: unknown[]) => validateTarget(...args),
  createProject: (...args: unknown[]) => createProject(...args),
  createScan: (...args: unknown[]) => createScan(...args),
  listProjects: (...args: unknown[]) => listProjects(...args),
  ApiError,
}));

vi.mock("@/lib/guard", () => ({
  hasSession: () => hasSession(),
}));

async function post(body: unknown) {
  const { POST } = await import("./route");
  return POST(new Request("http://dashboard.test/api/scans", { method: "POST", body: JSON.stringify(body) }));
}

beforeEach(() => {
  hasSession.mockResolvedValue(true);
  listProjects.mockResolvedValue({ data: [] });
  validateTarget.mockResolvedValue({ target: {} });
  createProject.mockResolvedValue({ id: "project-1" });
  createScan.mockResolvedValue({ id: "scan-1" });
});

describe("POST /api/scans", () => {
  it("requires a session", async () => {
    hasSession.mockResolvedValue(false);

    const response = await post({ repository_url: "https://github.com/o/r.git" });

    expect(response.status).toBe(401);
    // An anonymous page able to queue clones is a way to make the worker fetch
    // arbitrary URLs (ADR 029), so nothing may run before this gate.
    expect(validateTarget).not.toHaveBeenCalled();
    expect(createProject).not.toHaveBeenCalled();
  });

  /**
   * The defect this fix exists for.
   *
   * Submitting the SSRF probe used to leave a project called
   * `site-169-254-169-254-latest-meta-data` with zero scans: the address policy
   * refused the target, and the project created moments earlier stayed.
   */
  it("creates nothing when the API refuses the target", async () => {
    validateTarget.mockRejectedValue(
      new ApiError(400, "invalid target: address is not an allowed target: cloud instance metadata endpoint"),
    );

    const response = await post({
      repository_url: "https://169.254.169.254/latest/meta-data/",
      kind: "endpoint",
    });

    expect(response.status).toBe(400);
    expect(createProject).not.toHaveBeenCalled();
    expect(createScan).not.toHaveBeenCalled();

    // The API's own wording reaches the person who typed the URL, rather than
    // being replaced by something vaguer.
    await expect(response.json()).resolves.toMatchObject({
      error: expect.stringContaining("cloud instance metadata endpoint"),
    });
  });

  it("validates before it creates, not after", async () => {
    const order: string[] = [];
    validateTarget.mockImplementation(async () => {
      order.push("validate");
      return { target: {} };
    });
    createProject.mockImplementation(async () => {
      order.push("createProject");
      return { id: "project-1" };
    });
    createScan.mockImplementation(async () => {
      order.push("createScan");
      return { id: "scan-1" };
    });

    await post({ repository_url: "https://github.com/o/r.git" });

    expect(order).toEqual(["validate", "createProject", "createScan"]);
  });

  it("submits a repository target with its ref", async () => {
    const response = await post({ repository_url: "https://github.com/owner/repo.git" });

    expect(response.status).toBe(200);
    expect(createScan).toHaveBeenCalledWith({
      project_id: "project-1",
      target: { kind: "repository", repository_url: "https://github.com/owner/repo.git", ref: "main" },
      branch: "main",
    });
  });

  it("submits an endpoint target with no ref", async () => {
    await post({ repository_url: "https://example.com", kind: "endpoint" });

    expect(createScan).toHaveBeenCalledWith({
      project_id: "project-1",
      target: { kind: "endpoint", endpoint_url: "https://example.com" },
    });
  });

  it("reuses an existing project rather than splitting its history", async () => {
    listProjects.mockResolvedValue({ data: [{ id: "existing", slug: "owner-repo" }] });

    const response = await post({ repository_url: "https://github.com/owner/repo.git" });

    expect(createProject).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({ project_id: "existing" });
  });

  /**
   * A repository and its deployed site can share a path. Folding them into one
   * project would put findings about source code and findings about a running
   * application under one risk score, without either having been correlated to
   * the other.
   */
  it("gives a website its own project, distinct from a repository at the same path", async () => {
    await post({ repository_url: "https://example.com/app", kind: "endpoint" });
    const website = createProject.mock.calls[0]?.[0] as { slug: string };

    createProject.mockClear();
    await post({ repository_url: "https://example.com/app" });
    const repository = createProject.mock.calls[0]?.[0] as { slug: string };

    expect(website.slug).not.toBe(repository.slug);
    expect(website.slug.startsWith("site-")).toBe(true);
  });

  it("rejects a non-https URL without asking the API", async () => {
    const response = await post({ repository_url: "ftp://example.com" });

    expect(response.status).toBe(400);
    expect(validateTarget).not.toHaveBeenCalled();
  });

  it("reports an unreachable API as unreachable, not as a bad URL", async () => {
    validateTarget.mockRejectedValue(new TypeError("fetch failed"));

    const response = await post({ repository_url: "https://github.com/o/r.git" });

    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toMatchObject({ error: "The API is unreachable." });
  });
});
