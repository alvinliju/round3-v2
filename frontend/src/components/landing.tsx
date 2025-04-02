"use client";

import { useEffect } from "react";
import { motion, stagger, useAnimate } from "motion/react";
import { Badge } from "./ui/badge";

import Floating, {
  FloatingElement,
} from "@/fancy/components/image/parallax-floating";
import Link from "next/link";

const exampleImages = [
  {
    url: "https://images.unsplash.com/photo-1721968317938-cf8c60fccd1a?q=80&w=2728&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D",
  },
  {
    url: "https://i.pinimg.com/736x/98/79/ae/9879aeda3f03cfbbdcb9640593042388.jpg",
  },
  {
    url: "https://i.pinimg.com/736x/0f/fd/21/0ffd21b0f59bd452bee5f828e5c8ebd0.jpg",
  },
  {
    url: "https://i.pinimg.com/736x/9d/e9/2c/9de92c27d8a65bf2323e303268aac824.jpg",
  },
  {
    url: "https://i.pinimg.com/736x/5a/e3/53/5ae3536c1d0e2b6155331e5312ab67d9.jpg",
  },
  {
    url: "https://i.pinimg.com/736x/ab/1d/2d/ab1d2dc7624997b949989093061a30d9.jpg",
  },
  {
    url: "https://i.pinimg.com/736x/da/22/19/da22191a5be9f5a91452af1518a46e6c.jpg",
  },
  {
    url: "https://i.pinimg.com/736x/c5/80/59/c5805938f33da2e22a1a4d407dbf99a4.jpg",
  },
];

const Landing = () => {
  const [scope, animate] = useAnimate();

  useEffect(() => {
    animate(
      "img",
      { opacity: [0, 1] },
      { duration: 0.5, delay: stagger(0.15) },
    );
  }, []);

  return (
    <div
      className="flex w-dvw h-dvh justify-center items-center bg-black overflow-hidden p-4"
      ref={scope}
    >
      <motion.div
        className="z-50 text-center space-y-4 items-center flex flex-col"
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.88, delay: 1.5 }}
      >
        <Badge variant="secondary">Launching soon.</Badge>

        <p className="text-5xl md:text-7xl z-50 text-white font-calendas italic">
          round3.
        </p>
        <p className="text-xl md:text-2xl z-50 text-white font-calendas max-w-2xl backdrop-blur-1">
          A private community where founders share the real journey and readers
          invest in tomorrow's success stories.
        </p>
        <div className="flex gap-4">
          <p className="text-xs z-50 hover:scale-110 transition-transform bg-white text-black rounded-full py-2 w-32 cursor-pointer">
            <Link href="/login">Join the community</Link>
          </p>
          <p className="text-xs z-50 hover:scale-110 transition-transform border border-white text-white rounded-full py-2 w-32 cursor-pointer">
            <Link href="/how-it-works">How it works</Link>
          </p>
        </div>
      </motion.div>

      <Floating
        sensitivity={-1}
        className="overflow-hidden opacity-25 sm:opacity-100"
      >
        <FloatingElement depth={0.5} className="top-[8%] left-[11%]">
          <motion.img
            initial={{ opacity: 0 }}
            src={exampleImages[0].url}
            className="w-16 h-16 md:w-24 md:h-24 object-cover hover:scale-105 duration-200 cursor-pointer transition-transform"
          />
        </FloatingElement>
        <FloatingElement depth={1} className="top-[10%] left-[32%]">
          <motion.img
            initial={{ opacity: 0 }}
            src={exampleImages[1].url}
            className="w-20 h-20 md:w-28 md:h-28 object-cover hover:scale-105 duration-200 cursor-pointer transition-transform"
          />
        </FloatingElement>
        <FloatingElement depth={2} className="top-[2%] left-[53%]">
          <motion.img
            initial={{ opacity: 0 }}
            src={exampleImages[2].url}
            className="w-28 h-40 md:w-40 md:h-52 object-cover hover:scale-105 duration-200 cursor-pointer transition-transform"
          />
        </FloatingElement>
        <FloatingElement depth={1} className="top-[0%] left-[83%]">
          <motion.img
            initial={{ opacity: 0 }}
            src={exampleImages[3].url}
            className="w-24 h-24 md:w-32 md:h-32 object-cover hover:scale-105 duration-200 cursor-pointer transition-transform"
          />
        </FloatingElement>

        <FloatingElement depth={1} className="top-[40%] left-[2%]">
          <motion.img
            initial={{ opacity: 0 }}
            src={exampleImages[4].url}
            className="w-28 h-28 md:w-36 md:h-36 object-cover hover:scale-105 duration-200 cursor-pointer transition-transform"
          />
        </FloatingElement>
        <FloatingElement depth={2} className="top-[70%] left-[77%]">
          <motion.img
            initial={{ opacity: 0 }}
            src={exampleImages[5].url}
            className="w-28 h-28 md:w-36 md:h-48 object-cover hover:scale-105 duration-200 cursor-pointer transition-transform"
          />
        </FloatingElement>

        <FloatingElement depth={4} className="top-[73%] left-[15%]">
          <motion.img
            initial={{ opacity: 0 }}
            src={exampleImages[6].url}
            className="w-40 md:w-52 h-full object-cover hover:scale-105 duration-200 cursor-pointer transition-transform"
          />
        </FloatingElement>
        <FloatingElement depth={1} className="top-[80%] left-[50%]">
          <motion.img
            initial={{ opacity: 0 }}
            src={exampleImages[7].url}
            className="w-24 h-24 md:w-32 md:h-32 object-cover hover:scale-105 duration-200 cursor-pointer transition-transform"
          />
        </FloatingElement>
      </Floating>
    </div>
  );
};

export default Landing;
