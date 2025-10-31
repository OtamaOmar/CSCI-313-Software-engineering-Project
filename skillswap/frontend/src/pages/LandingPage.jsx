import React from "react";
import { useNavigate } from "react-router-dom"; // ✅ import navigation hook

export default function LandingPage() {
  const navigate = useNavigate(); // ✅ initialize navigate

  return (
    <div className="min-h-screen overflow-y-scroll bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100 flex flex-col">
      {/* Navbar */}
      <header className="w-full flex items-center justify-between px-8 py-4 border-b border-gray-200 dark:border-gray-800">
        <h1 className="text-2xl font-semibold text-primary">SkillSwap</h1>

        <div className="flex items-center gap-4">
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
        </div>
      </header>

      {/* Hero Section */}
      <section className="flex-1 flex flex-col items-center justify-center text-center px-6 py-20">
        <h2 className="text-4xl md:text-6xl font-bold mb-6 leading-tight">
          Learn. Teach. Grow. <br />
          <span className="text-primary">Together.</span>
        </h2>
        <p className="max-w-2xl text-gray-600 dark:text-gray-300 mb-10">
          SkillSwap connects students who want to teach and learn from each
          other — from coding and design to languages and life skills.
        </p>
        <div className="flex gap-4">
          {/* ✅ Redirects to /login */}
          <button
            onClick={() => navigate("/login")}
            className="btn btn-primary cursor-pointer"
          >
            Get Started
          </button>

          <button
            onClick={() => navigate("/learn-more")}
            className="btn btn-outline cursor-pointer"
          >
            Learn More
          </button>
        </div>
      </section>

      {/* Features Section */}
      <section
        id="features"
        className="py-20 px-6 bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-800"
      >
        <div className="max-w-5xl mx-auto text-center">
          <h3 className="text-3xl font-semibold mb-10">Why SkillSwap?</h3>
          <div className="grid md:grid-cols-3 gap-10 text-left">
            {[
              {
                title: "Peer Learning",
                desc: "Connect with others who share your curiosity. Learn from real students like you.",
              },
              {
                title: "Skill Matching",
                desc: "Our algorithm matches you with peers offering the exact skills you want.",
              },
              {
                title: "Flexible Scheduling",
                desc: "Book lessons that fit your time — anytime, anywhere.",
              },
            ].map((f, i) => (
              <div
                key={i}
                className="p-6 rounded-2xl bg-white dark:bg-gray-800 shadow-sm hover:shadow-md transition-shadow"
              >
                <h4 className="text-xl font-semibold text-primary mb-2">
                  {f.title}
                </h4>
                <p className="text-gray-600 dark:text-gray-300">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Testimonials Section */}
      <section
        id="reviews"
        className="py-20 px-6 bg-white dark:bg-gray-950 border-t border-gray-200 dark:border-gray-800"
      >
        <div className="max-w-5xl mx-auto text-center">
          <h3 className="text-3xl font-semibold mb-10">What Our Students Say</h3>
          <div className="grid md:grid-cols-2 gap-8">
            <div className="p-6 rounded-2xl bg-gray-50 dark:bg-gray-900 shadow-sm">
              <p className="italic mb-4">
                “SkillSwap helped me learn JavaScript while teaching Photoshop.
                It’s genius!”
              </p>
              <p className="font-semibold text-primary">— Hamza, Design Student</p>
            </div>
            <div className="p-6 rounded-2xl bg-gray-50 dark:bg-gray-900 shadow-sm">
              <p className="italic mb-4">
                “I improved my English by tutoring someone in Python. A win-win
                experience.”
              </p>
              <p className="font-semibold text-primary">
                — Omar, CS Undergrad
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer
        id="contact"
        className="mt-auto py-6 text-center text-sm text-gray-500 dark:text-gray-400 border-t border-gray-200 dark:border-gray-800"
      >
        © {new Date().getFullYear()} SkillSwap. All rights reserved.
      </footer>
    </div>
  );
}