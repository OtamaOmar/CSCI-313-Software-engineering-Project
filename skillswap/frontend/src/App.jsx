import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";

import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import SignUp from "./pages/SignUp";
import LearnMorePage from "./pages/LearnMorePage";
import FeedPage from "./pages/FeedPage";
import ProfilePage from "./pages/ProfilePage";
import ChatPage from "./pages/chat";
import ForgetPassPage from "./pages/ForgetPassPage";
import ProtectedRoute from "./components/ProtectedRoute";

export default function App() {
  return (
    <Router>
      <Routes>

        {/* 🏠 Default Landing Page */}
        <Route path="/" element={<LandingPage />} />

        {/* 🔐 Login Page */}
        <Route path="/login" element={<LoginPage />} />

        {/* ✍️ Sign Up Page */}
        <Route path="/signup" element={<SignUp />} />

        {/* 📚 Learn More Page */}
        <Route path="/learn-more" element={<LearnMorePage />} />

        {/* 📰 FEED PAGE (Protected) */}
        <Route path="/feed" element={<ProtectedRoute><FeedPage /></ProtectedRoute>} />

        {/* 👤 PROFILE PAGE (Protected) */}
        <Route path="/profile" element={<ProtectedRoute><ProfilePage /></ProtectedRoute>} />

        {/* 💬 CHAT PAGE (Protected) */}
        <Route path="/chat" element={<ProtectedRoute><ChatPage /></ProtectedRoute>} />

        {/* 🔁 Forgot Password */}
        <Route path="/forget-password" element={<ForgetPassPage />} />

      </Routes>
    </Router>
  );
}