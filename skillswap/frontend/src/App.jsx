import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage"; // ✅ Import the login page
import LearnMorePage from "./pages/LearnMorePage";

// 🔧 Optional: Future pages can be added here
// import Dashboard from "./pages/Dashboard";
// import Profile from "./pages/Profile";

export default function App() {
  return (
    <Router>
      <Routes>
        {/* 🏠 Default Landing Page */}
        <Route path="/" element={<LandingPage />} />

        {/* 🔐 Login Page */}
        <Route path="/login" element={<LoginPage />} />

        {/* 📚 Learn More Page */}
        <Route path="/learn-more" element={<LearnMorePage />} />

        {/* 🧭 Future routes (uncomment when ready) */}
        {/* <Route path="/dashboard" element={<Dashboard />} /> */}
        {/* <Route path="/profile" element={<Profile />} /> */}
      </Routes>
    </Router>
  );
}