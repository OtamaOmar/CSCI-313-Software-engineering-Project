import React, { useState } from "react";
import { Eye, EyeOff, X } from "lucide-react";

export default function LoginPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [showError, setShowError] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    // TODO: Replace with actual login API call
    setError("Invalid email or password. Please try again.");
    setShowError(true);
  };

  const closeError = () => {
    setShowError(false);
    setError("");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-white text-gray-900 dark:bg-gray-950 dark:text-gray-100 transition-colors duration-300">
      <div className="w-full max-w-md bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-2xl shadow-lg p-8">
        {/* Header */}
        <h1 className="text-3xl font-bold text-center text-primary mb-2">
          Welcome Back
        </h1>
        <p className="text-center text-gray-600 dark:text-gray-400 mb-8">
          Log in to continue your SkillSwap journey
        </p>

        {/* Error Message Popout */}
        {showError && (
          <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-start gap-3 animate-in fade-in slide-in-from-top-2">
            <div className="flex-1">
              <p className="text-sm font-medium text-red-800 dark:text-red-200">
                {error}
              </p>
            </div>
            <button
              onClick={closeError}
              className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 shrink-0 cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        )}

        {/* Form */}
        <form className="flex flex-col gap-5" onSubmit={handleSubmit}>
          {/* Email */}
          <div className="flex flex-col gap-2">
            <label htmlFor="email" className="text-sm font-medium">
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              className="px-4 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 focus:ring-2 focus:ring-primary focus:outline-none transition"
              placeholder="you@example.com"
            />
          </div>

          {/* Password */}
          <div className="flex flex-col gap-2 relative">
            <label htmlFor="password" className="text-sm font-medium">
              Password
            </label>
            <input
              id="password"
              type={showPassword ? "text" : "password"}
              required
              className="px-4 py-2 w-full rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 focus:ring-2 focus:ring-primary focus:outline-none transition pr-10"
              placeholder="••••••••"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-9 text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 cursor-pointer"
            >
              {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>

          {/* Remember me & Forgot password */}
          <div className="flex items-center justify-between text-sm">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                className="accent-primary"
              />
              Remember me
            </label>
            <a
              href="#"
              className="text-primary hover:underline cursor-pointer transition-colors"
            >
              Forgot password?
            </a>
          </div>

          {/* Login button */}
          <button
            type="submit"
            className="btn btn-primary w-full cursor-pointer"
          >
            Log In
          </button>

          {/* Sign up link */}
          <p className="text-center text-sm text-gray-600 dark:text-gray-400 mt-4">
            Don't have an account?{" "}
            <a href="#" className="text-primary hover:underline cursor-pointer transition-colors">
              Sign up
            </a>
          </p>
        </form>
      </div>
    </div>
  );
}