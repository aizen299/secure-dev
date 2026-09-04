"use client";

import * as React from "react";
import { MonitorIcon, MoonIcon, SunIcon } from "lucide-react";
import { cn } from "@/lib/utils";

type Theme = "light" | "dark" | "system";

const STORAGE_KEY = "secureops-theme";

function apply(theme: Theme) {
  const root = document.documentElement;
  const dark =
    theme === "dark" ||
    (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  root.classList.toggle("light", !dark);
  root.style.colorScheme = dark ? "dark" : "light";
}

/**
 * Theme selection: light, dark, or follow the system.
 *
 * Three states rather than a two-way toggle. "System" is the honest default --
 * a security console someone opens at 3am should match the rest of their
 * machine rather than deciding for them -- and it is a real setting, not the
 * absence of one.
 *
 * The choice is stored per browser. It is a display preference, so it belongs
 * in localStorage rather than in a cookie the server has to carry.
 */
/**
 * A tiny store over localStorage.
 *
 * useSyncExternalStore rather than useState-in-an-effect: reading storage
 * during render is impure and setting state from an effect cascades a render
 * on every mount. This is the primitive React provides for exactly this shape
 * -- a value that differs between server and client and can change underneath
 * the component.
 */
let listeners: (() => void)[] = [];

function subscribe(listener: () => void) {
  listeners.push(listener);
  const onStorage = () => listener();
  window.addEventListener("storage", onStorage);
  return () => {
    listeners = listeners.filter((l) => l !== listener);
    window.removeEventListener("storage", onStorage);
  };
}

function getSnapshot(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === "light" || stored === "dark" ? stored : "system";
  } catch {
    // Private browsing, or storage disabled. Following the system is the right
    // fallback: it is what the user already chose everywhere else.
    return "system";
  }
}

/** The server has no preference to read, and must not guess one. */
function getServerSnapshot(): Theme {
  return "system";
}

function setTheme(theme: Theme) {
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // A theme that cannot be remembered still applies for this page.
  }
  apply(theme);
  for (const listener of listeners) listener();
}

/**
 * Theme selection: light, dark, or follow the system.
 *
 * Three states rather than a two-way toggle. "System" is the honest default --
 * a console someone opens at 3am should match the rest of their machine rather
 * than deciding for them -- and it is a real setting, not the absence of one.
 */
export function ThemeToggle({ className }: { className?: string }) {
  const theme = React.useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  React.useEffect(() => {
    if (theme !== "system") return;
    // Following the system means following it as it changes, not once at load.
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => apply("system");
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [theme]);

  const options: { value: Theme; Icon: typeof SunIcon; label: string }[] = [
    { value: "light", Icon: SunIcon, label: "Light" },
    { value: "dark", Icon: MoonIcon, label: "Dark" },
    { value: "system", Icon: MonitorIcon, label: "System" },
  ];

  return (
    <div
      className={cn("flex items-center gap-0.5 rounded-md border border-line p-0.5", className)}
      role="group"
      aria-label="Colour theme"
    >
      {options.map(({ value, Icon, label }) => (
        <button
          key={value}
          type="button"
          onClick={() => setTheme(value)}
          aria-label={label}
          aria-pressed={theme === value}
          title={label}
          className={cn(
            "flex size-5 items-center justify-center rounded transition-colors duration-100",
            theme === value ? "bg-raised text-ink" : "text-ink-faint hover:text-ink-muted",
          )}
        >
          <Icon className="size-3" />
        </button>
      ))}
    </div>
  );
}

export function ThemeScript() {
  const script = `(function(){try{var t=localStorage.getItem(${JSON.stringify(STORAGE_KEY)})||"system";var d=t==="dark"||(t==="system"&&matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.classList.toggle("light",!d);document.documentElement.style.colorScheme=d?"dark":"light";}catch(e){}})();`;
  return <script dangerouslySetInnerHTML={{ __html: script }} />;
}
