import { div } from "motion/react-client";
import Image from "next/image";
import Landing from "@/components/landing";

export default function Home() {
  return (
    <div className="w-full max-h-screen bg-slate-950">
      <Landing />
    </div>
  );
}
