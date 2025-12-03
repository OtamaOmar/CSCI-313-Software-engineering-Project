import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";

import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage"; // ✅ Import the login page
import LearnMorePage from "./pages/LearnMorePage";
import FeedPage from "./pages/FeedPage";
import ProfilePage from "./pages/ProfilePage";
import ChatPage from "./pages/chat";
import ForgetPassPage from "./pages/ForgetPassPage";

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

        {/* 📰 FEED PAGE (NEW) */}
        <Route path="/feed" element={<FeedPage />} />

        {/* 👤 PROFILE PAGE */}
        <Route path="/profile" element={<ProfilePage />} />

        {/* 💬 CHAT PAGE */}
        <Route path="/chat" element={<ChatPage />} />

        {/* 🔁 Forgot Password */}
        <Route path="/forget-password" element={<ForgetPassPage />} />

      </Routes>
    </Router>
  );
}