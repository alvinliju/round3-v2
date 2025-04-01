"use client";

import { motion } from "motion/react";
import Link from "next/link";
import Navbar from "@/components/Navbar";

const HowItWorks = () => {
  return (
    <div className="flex flex-col min-h-dvh bg-black text-white font-calendas p-4 md:p-8">
      {/* Navigation */}
      <Navbar />

      {/* Header */}
      <motion.div
        className="text-center mb-16 md:mb-24"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <h1 className="text-4xl md:text-5xl italic mb-4">How round3 works</h1>
        <p className="text-xl max-w-2xl mx-auto text-gray-300">
          A community platform connecting founders and their supporters through
          authentic stories and direct funding.
        </p>
      </motion.div>

      {/* Steps Section */}
      <div className="grid md:grid-cols-2 gap-16 md:gap-24 max-w-5xl mx-auto">
        {/* For Founders */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          <div className="flex items-center mb-6">
            <div className="w-12 h-12 rounded-full bg-white text-black flex items-center justify-center text-xl mr-4">
              F
            </div>
            <h2 className="text-2xl md:text-3xl">For Founders</h2>
          </div>

          <div className="space-y-10 pl-16">
            <div>
              <p className="text-lg font-medium mb-2">Share your journey</p>
              <p className="text-gray-300">
                Document your startup's real challenges and victories in an
                authentic way.
              </p>
            </div>

            <div>
              <p className="text-lg font-medium mb-2">Build in public</p>
              <p className="text-gray-300">
                Create transparency that builds trust with potential investors
                and supporters.
              </p>
            </div>

            <div>
              <p className="text-lg font-medium mb-2">Get funded by peers</p>
              <p className="text-gray-300">
                Connect directly with readers who believe in your vision and
                want to invest.
              </p>
            </div>
          </div>
        </motion.div>

        {/* For Readers */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
        >
          <div className="flex items-center mb-6">
            <div className="w-12 h-12 rounded-full bg-white text-black flex items-center justify-center text-xl mr-4">
              R
            </div>
            <h2 className="text-2xl md:text-3xl">For Readers</h2>
          </div>

          <div className="space-y-10 pl-16">
            <div>
              <p className="text-lg font-medium mb-2">Get real updates</p>
              <p className="text-gray-300">
                Access unfiltered, real-time stories from founders who are
                actively building.
              </p>
            </div>

            <div>
              <p className="text-lg font-medium mb-2">Learn from battles</p>
              <p className="text-gray-300">
                Gain insights from founders' challenges, pivots, and strategies
                as they happen.
              </p>
            </div>

            <div>
              <p className="text-lg font-medium mb-2">Support for $5/month</p>
              <p className="text-gray-300">
                Subscribe for exclusive content and opportunities to invest in
                startups you believe in.
              </p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Call to Action */}
      <motion.div
        className="text-center mt-24 mb-16"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.6 }}
      >
        <h2 className="text-2xl md:text-3xl mb-6">Ready to join round3?</h2>
        <div className="flex gap-4 justify-center">
          <Link href="/founder-signup">
            <p className="px-6 py-3 bg-white text-black rounded-full hover:bg-gray-200 cursor-pointer">
              Join as Founder
            </p>
          </Link>
          <Link href="/reader-signup">
            <p className="px-6 py-3 border border-white rounded-full hover:bg-white hover:text-black transition-colors cursor-pointer">
              Join as Reader
            </p>
          </Link>
        </div>
      </motion.div>

      {/* Footer */}
      <footer className="mt-auto py-8 text-center text-sm text-gray-500">
        <p>© {new Date().getFullYear()} round3. All rights reserved.</p>
      </footer>
    </div>
  );
};

export default HowItWorks;
