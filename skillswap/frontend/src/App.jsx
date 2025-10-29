import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage"; // ✅ Import the login page

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

        {/* 🧭 Future routes (uncomment when ready) */}
        {/* <Route path="/dashboard" element={<Dashboard />} /> */}
        {/* <Route path="/profile" element={<Profile />} /> */}
      </Routes>
    </Router>
  );
}