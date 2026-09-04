import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScanBar } from "./scan-bar";

/**
 * The scan mode is one piece of state, and every field must agree with it.
 *
 * This is the test that would have caught the defect this component was
 * rewritten for: selecting "Website" left the page headed SCAN A REPOSITORY,
 * with a repository placeholder and a "Scan repository" button, because the
 * heading was rendered by the page above and the state had no way to reach it.
 *
 * So the assertions are deliberately about *agreement* rather than about any
 * one field. Checking only the placeholder would have passed against the
 * broken version.
 */

const push = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push, refresh: vi.fn() }),
}));

/** Every field the mode drives, read from the rendered output. */
function surface() {
  const field = screen.getByRole("textbox") as HTMLInputElement;
  return {
    // The visible heading is whichever crossfade layer is not aria-hidden. Both
    // are always in the DOM -- that is how the crossfade avoids depending on an
    // exit callback -- so "which one is exposed" is the real question.
    heading: screen
      .getAllByRole("heading", { level: 2 })
      .find((h) => h.closest("[aria-hidden='true']") === null)?.textContent,
    placeholder: field.placeholder,
    label: screen.getByLabelText(/URL$/).getAttribute("placeholder"),
    submit: screen.getByRole("button", { name: /^Scan / }).textContent,
  };
}

beforeEach(() => {
  push.mockReset();
});

describe("ScanBar", () => {
  it("starts in repository mode with every field agreeing", () => {
    render(<ScanBar />);
    const s = surface();

    expect(s.heading).toBe("Scan a repository");
    expect(s.placeholder).toBe("https://github.com/owner/repository");
    expect(s.submit).toBe("Scan repository");
    expect(screen.getByRole("radio", { name: /git repository/i })).toBeChecked();
  });

  it("switches every field together when the website mode is selected", async () => {
    const user = userEvent.setup();
    render(<ScanBar />);

    await user.click(screen.getByRole("radio", { name: /running website/i }));

    const s = surface();
    expect(s.heading).toBe("Scan a website");
    expect(s.placeholder).toBe("https://your-app.example.com");
    expect(s.submit).toBe("Scan website");
    expect(screen.getByRole("radio", { name: /running website/i })).toBeChecked();
    expect(screen.getByRole("radio", { name: /git repository/i })).not.toBeChecked();
  });

  /**
   * The contradiction, stated directly.
   *
   * Every other assertion here would still pass if one field lagged behind, as
   * long as the field it checked happened to be one of the ones that updated.
   * This one fails whenever the visible heading names a different mode than the
   * checked radio, whichever way round the mismatch falls.
   */
  it("never shows a heading that disagrees with the selected mode", async () => {
    const user = userEvent.setup();
    render(<ScanBar />);

    for (const [name, heading] of [
      [/running website/i, "Scan a website"],
      [/git repository/i, "Scan a repository"],
      [/running website/i, "Scan a website"],
    ] as const) {
      await user.click(screen.getByRole("radio", { name }));
      expect(screen.getByRole("radio", { name })).toBeChecked();
      expect(surface().heading).toBe(heading);
    }
  });

  it("returns to repository mode intact", async () => {
    const user = userEvent.setup();
    render(<ScanBar />);

    await user.click(screen.getByRole("radio", { name: /running website/i }));
    await user.click(screen.getByRole("radio", { name: /git repository/i }));

    expect(surface()).toMatchObject({
      heading: "Scan a repository",
      placeholder: "https://github.com/owner/repository",
      submit: "Scan repository",
    });
  });

  it("keeps a typed URL when the mode changes", async () => {
    const user = userEvent.setup();
    render(<ScanBar />);

    const field = screen.getByRole("textbox");
    await user.type(field, "https://example.com");
    await user.click(screen.getByRole("radio", { name: /running website/i }));

    // Someone who pasted a URL and then realised they picked the wrong kind
    // should not have to paste it again.
    expect(field).toHaveValue("https://example.com");
  });

  describe("validation", () => {
    it("reports the repository wording for a bad repository URL", async () => {
      const user = userEvent.setup();
      render(<ScanBar />);

      await user.type(screen.getByRole("textbox"), "ftp://nope");
      await user.click(screen.getByRole("button", { name: /^Scan / }));

      expect(await screen.findByRole("alert")).toHaveTextContent(
        "Enter an https repository URL.",
      );
    });

    it("reports the website wording for a bad website URL", async () => {
      const user = userEvent.setup();
      render(<ScanBar />);

      await user.click(screen.getByRole("radio", { name: /running website/i }));
      await user.type(screen.getByRole("textbox"), "ftp://nope");
      await user.click(screen.getByRole("button", { name: /^Scan / }));

      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent("Enter an https URL.");
      expect(alert).not.toHaveTextContent("repository");
    });

    it("clears an error when the mode changes", async () => {
      const user = userEvent.setup();
      render(<ScanBar />);

      await user.type(screen.getByRole("textbox"), "ftp://nope");
      await user.click(screen.getByRole("button", { name: /^Scan / }));
      expect(await screen.findByRole("alert")).toBeInTheDocument();

      // An error about the other mode's rules must not survive the switch.
      await user.click(screen.getByRole("radio", { name: /running website/i }));
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });
  });

  describe("the mode selector", () => {
    it("is a radiogroup, so a screen reader announces a selection", () => {
      render(<ScanBar />);
      const group = screen.getByRole("radiogroup", { name: /what to scan/i });

      expect(within(group).getAllByRole("radio")).toHaveLength(2);
    });

    it("moves between options with the arrow keys", async () => {
      const user = userEvent.setup();
      render(<ScanBar />);

      const repository = screen.getByRole("radio", { name: /git repository/i });
      const website = screen.getByRole("radio", { name: /running website/i });

      repository.focus();
      await user.keyboard("{ArrowRight}");
      expect(website).toBeChecked();
      expect(website).toHaveFocus();

      await user.keyboard("{ArrowLeft}");
      expect(repository).toBeChecked();
    });

    it("wraps at the ends rather than stopping", async () => {
      const user = userEvent.setup();
      render(<ScanBar />);

      screen.getByRole("radio", { name: /git repository/i }).focus();
      await user.keyboard("{ArrowLeft}");

      expect(screen.getByRole("radio", { name: /running website/i })).toBeChecked();
    });

    /**
     * Roving tabindex: only the selected option is tabbable, so Tab moves past
     * the whole control to the field below rather than stepping through it.
     */
    it("exposes exactly one tab stop", async () => {
      const user = userEvent.setup();
      render(<ScanBar />);

      const radios = screen.getAllByRole("radio");
      expect(radios.filter((r) => r.getAttribute("tabindex") === "0")).toHaveLength(1);

      await user.click(screen.getByRole("radio", { name: /running website/i }));
      expect(radios.filter((r) => r.getAttribute("tabindex") === "0")).toHaveLength(1);
      expect(screen.getByRole("radio", { name: /running website/i })).toHaveAttribute(
        "tabindex",
        "0",
      );
    });
  });

  describe("submitting", () => {
    it("sends the selected kind", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ project_id: "p1", scan_id: "s1" }),
      });
      vi.stubGlobal("fetch", fetchMock);

      const user = userEvent.setup();
      render(<ScanBar />);

      await user.click(screen.getByRole("radio", { name: /running website/i }));
      await user.type(screen.getByRole("textbox"), "https://example.com");
      await user.click(screen.getByRole("button", { name: /^Scan / }));

      expect(fetchMock).toHaveBeenCalledWith(
        "/api/scans",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ repository_url: "https://example.com", kind: "endpoint" }),
        }),
      );
    });

    it("shows what the API rejected, verbatim", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: false,
          json: async () => ({ error: "invalid target: cloud instance metadata endpoint" }),
        }),
      );

      const user = userEvent.setup();
      render(<ScanBar />);

      await user.click(screen.getByRole("radio", { name: /running website/i }));
      await user.type(screen.getByRole("textbox"), "https://169.254.169.254/latest/");
      await user.click(screen.getByRole("button", { name: /^Scan / }));

      // Not paraphrased: "scheme must be https" or "blocked address" is exactly
      // what the person typing needs to read.
      expect(await screen.findByRole("alert")).toHaveTextContent(
        "cloud instance metadata endpoint",
      );
    });

    it("does not submit an empty field", async () => {
      render(<ScanBar />);
      expect(screen.getByRole("button", { name: /^Scan / })).toBeDisabled();
    });
  });
});
