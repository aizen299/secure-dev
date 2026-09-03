import { redirect } from "next/navigation";

// Projects are the only top-level concept; a separate landing page would be a
// page whose entire content is one link.
export default function Home() {
  redirect("/projects");
}
