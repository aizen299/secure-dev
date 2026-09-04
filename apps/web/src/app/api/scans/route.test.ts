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
  MAX_PAGE: 100,
  // The real implementation, because paging is the behaviour under test in
  // "reads every page" below -- a stub that returned one page would make that
  // test pass against the bug it exists for.
  collect: async (
    page: (limit: number, offset: number) => Promise<{ items: unknown[]; hasMore: boolean }>,
    maxPages = 10,
  ) => {
    const items: unknown[] = [];
    for (let i = 0; i < maxPages; i++) {
      const { items: batch, hasMore } = await page(100, i * 100);
      items.push(...batch);
      if (!hasMore) return { items, truncated: false };
    }
    return { items, truncated: true };
  },
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
  listProjects.mockResolvedValue({ data: [], pagination: { limit: 100, offset: 0, has_more: false } });
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
    // The archived lookup runs only when the live one finds nothing, so one
    // resolved value serves both here.
    listProjects.mockResolvedValue({
      data: [{ id: "existing", slug: "owner-repo", name: "Owner Repo" }],
      pagination: { limit: 100, offset: 0, has_more: false },
    });

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

/**
 * Scanning a target whose project is archived.
 *
 * Reported from the dashboard: pasting a repository URL answered "a project
 * with that slug already exists" while the help text directly below promised
 * that scanning the same target again adds to its history. Both the error and
 * the promise were about a project the person could not see, because the slug
 * lookup listed live projects only and the project had been archived.
 *
 * The fix is a refusal rather than a reuse. An archived project accepts no new
 * scans by design, so finding it would only move the failure; restoring it
 * silently would undo a deliberate decision; and creating a second project for
 * the same target splits its history. What was missing was a message that says
 * which of those is happening.
 */
describe("a target whose project is archived", () => {
  it("says so, names the project, and creates nothing", async () => {
    listProjects.mockImplementation(async (params: { archived?: boolean }) =>
      params?.archived
        ? {
            data: [{ id: "p-archived", slug: "acme-app", name: "Acme App" }],
            pagination: { limit: 100, offset: 0, has_more: false },
          }
        : { data: [], pagination: { limit: 100, offset: 0, has_more: false } },
    );

    const response = await post({ repository_url: "https://github.com/acme/app.git" });
    const body = (await response.json()) as { error: string; project_id: string };

    expect(response.status).toBe(409);
    expect(body.error).toContain("Acme App");
    expect(body.error).toContain("archived");
    // The remedy, not just the diagnosis.
    expect(body.error).toMatch(/restore/i);
    expect(body.project_id).toBe("p-archived");

    // Nothing is created. A second project for the same target would split its
    // history in two, which is the outcome the slug exists to prevent.
    expect(createProject).not.toHaveBeenCalled();
    expect(createScan).not.toHaveBeenCalled();
  });

  it("reuses a live project rather than refusing it", async () => {
    listProjects.mockImplementation(async (params: { archived?: boolean }) =>
      params?.archived
        ? { data: [], pagination: { limit: 100, offset: 0, has_more: false } }
        : {
            data: [{ id: "p-live", slug: "acme-app", name: "Acme App" }],
            pagination: { limit: 100, offset: 0, has_more: false },
          },
    );

    const response = await post({ repository_url: "https://github.com/acme/app.git" });

    expect(response.status).toBe(200);
    expect(createProject).not.toHaveBeenCalled();
    expect(createScan).toHaveBeenCalledWith(
      expect.objectContaining({ project_id: "p-live" }),
    );
  });
});

/**
 * The latent half of the same defect.
 *
 * The lookup read one page of 100. Past that, a target's own project became
 * invisible here and the next scan of it collided on the unique index -- the
 * same "slug already exists" about a project that plainly does. It would have
 * appeared silently, at a threshold nobody would recognise.
 */
describe("finding a project among many", () => {
  it("reads every page rather than the first", async () => {
    const filler = (n: number, offset: number) =>
      Array.from({ length: n }, (_, i) => ({
        id: `p${offset + i}`,
        slug: `filler-${offset + i}`,
        name: `Filler ${offset + i}`,
      }));

    listProjects.mockImplementation(
      async (params: { offset?: number; archived?: boolean }) => {
        if (params?.archived) {
          return { data: [], pagination: { limit: 100, offset: 0, has_more: false } };
        }
        const offset = params?.offset ?? 0;
        // The match is on the SECOND page, which is what the single-page
        // version could never reach.
        return offset === 0
          ? { data: filler(100, 0), pagination: { limit: 100, offset: 0, has_more: true } }
          : {
              data: [{ id: "p-deep", slug: "acme-app", name: "Acme App" }],
              pagination: { limit: 100, offset, has_more: false },
            };
      },
    );

    const response = await post({ repository_url: "https://github.com/acme/app.git" });

    expect(response.status).toBe(200);
    expect(createProject).not.toHaveBeenCalled();
    expect(createScan).toHaveBeenCalledWith(expect.objectContaining({ project_id: "p-deep" }));
  });
});
