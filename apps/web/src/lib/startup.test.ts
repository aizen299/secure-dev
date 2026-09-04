/**
 * @vitest-environment node
 */
import { describe, expect, it } from "vitest";
import { assertNoRemovedSettings } from "./startup";

/**
 * A removed setting must stop the dashboard, not be ignored (ADR 033 §6a).
 *
 * Ignoring is the dangerous half. An operator with SECUREOPS_DASHBOARD_PASSWORD
 * still set would believe that credential works, and would find out otherwise
 * from somebody unable to sign in — at which point the obvious diagnosis is
 * "the login is broken" rather than "that setting no longer exists".
 */
describe("assertNoRemovedSettings", () => {
  it("refuses a configured shared password", () => {
    expect(() => assertNoRemovedSettings({ SECUREOPS_DASHBOARD_PASSWORD: "hunter2" })).toThrow(
      /SECUREOPS_DASHBOARD_PASSWORD/,
    );
  });

  // The error has to say what to do instead. "Removed" alone sends somebody
  // looking for a replacement setting that does not exist.
  it("says how to create an account instead", () => {
    expect(() => assertNoRemovedSettings({ SECUREOPS_DASHBOARD_PASSWORD: "hunter2" })).toThrow(
      /useradd/,
    );
  });

  it("allows an absent or blank value", () => {
    expect(() => assertNoRemovedSettings({})).not.toThrow();
    expect(() => assertNoRemovedSettings({ SECUREOPS_DASHBOARD_PASSWORD: "" })).not.toThrow();
    expect(() => assertNoRemovedSettings({ SECUREOPS_DASHBOARD_PASSWORD: "   " })).not.toThrow();
  });
});
