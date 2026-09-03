import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merges class names, resolving Tailwind conflicts in favour of the last. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
