import React from "react";
import { useNavigate } from "react-router-dom";

export default function LearnMore() {
  const navigate = useNavigate(); // ✅ Required for navigation

  return (
    <div className="min-h-screen overflow-y-scroll bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100 flex flex-col">
      {/* Navbar */}
      <header className="w-full flex items-center justify-between px-8 py-4 border-b border-gray-200 dark:border-gray-800">
        <h1 className="text-2xl font-semibold text-primary">SkillSwap</h1>

        <nav className="hidden md:flex gap-6 text-sm font-medium">
          <a href="#features" className="hover:text-primary transition-colors cursor-pointer">
            Features
          </a>
          <a href="#reviews" className="hover:text-primary transition-colors cursor-pointer">
            Reviews
          </a>
          <a href="#contact" className="hover:text-primary transition-colors cursor-pointer">
            Contact
          </a>
        </nav>
      </header>

      {/* Content */}
      <div className="min-h-screen px-8 py-16">
        <h1 className="text-4xl font-bold text-green-600 text-center mb-6">
          What is SkillSwap?
        </h1>

        <p className="max-w-3xl text-center mx-auto text-lg text-gray-600 dark:text-gray-300 mb-12">
          SkillSwap is a peer-to-peer learning platform where students teach and learn from each other.
          Instead of paying for courses, you share the skills you already know and gain the skills you need —
          making learning collaborative, affordable, and fun.
        </p>

        {/* How It Works */}
        <h2 className="text-4xl font-bold text-green-600 text-center mb-6">How It Works</h2>
        <div className="max-w-3xl mx-auto space-y-4 text-gray-700 dark:text-gray-400">
          <p>1️⃣ <strong>Create your profile</strong> — List skills you can teach & skills you want to learn.</p>
          <p>2️⃣ <strong>Match with others</strong> — Our system suggests students who complement your skills.</p>
          <p>3️⃣ <strong>Schedule a lesson</strong> — Pick a time that works for both of you.</p>
          <p>4️⃣ <strong>Learn & teach</strong> — Grow together and help each other improve.</p>
        </div>

        {/* Features */}
        <h2 className="text-4xl font-bold text-green-600 text-center mt-16 mb-6">Features</h2>
        <div className="grid md:grid-cols-3 gap-7 max-w-5xl mx-auto">
          <div className="p-6 rounded-xl bg-gray-50 dark:bg-gray-900 shadow-sm">
            <h3 className="text-xl font-semibold text-green-600 mb-2">Peer Learning</h3>
            <p>Learn from real students who understand your pace and background.</p>
          </div>

          <div className="p-6 rounded-xl bg-gray-50 dark:bg-gray-900 shadow-sm">
            <h3 className="text-xl font-semibold text-green-600 mb-2">Skill Matching</h3>
            <p>A smart algorithm matches you with people offering the skills you need.</p>
          </div>

          <div className="p-6 rounded-xl bg-gray-50 dark:bg-gray-900 shadow-sm">
            <h3 className="text-xl font-semibold text-green-600 mb-2">Flexible Scheduling</h3>
            <p>Choose lesson times that fit your daily routine easily.</p>
          </div>
        </div>

        {/* Call to Action */}
        <div className="text-center mt-16">
          <button
            onClick={() => navigate("/login")}
            className="px-6 py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg shadow-md transition cursor-pointer"
          >
            Get Started — It's Free 🚀
          </button>
        </div>
      </div>
    </div>
  );
}
