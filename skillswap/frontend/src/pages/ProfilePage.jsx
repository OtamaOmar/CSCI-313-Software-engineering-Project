import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Menu, Search, Users, LogOut, Mail, Bell, Edit, Camera, Calendar, Award, Home } from "lucide-react";
import { getCurrentUserProfile } from "../services/api";

export default function ProfilePage() {
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [darkMode] = useState(localStorage.getItem("theme") === "dark");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // User profile data from Supabase
  const [profile, setProfile] = useState(null);

  // Fetch user profile
  useEffect(() => {
    const fetchProfile = async () => {
      try {
        setLoading(true);
        const userProfile = await getCurrentUserProfile();
        setProfile(userProfile);
      } catch (err) {
        setError(err.message || "Failed to load profile");
        // If not authenticated, redirect to login
        if (err.message.includes("authentication")) {
          navigate("/login");
        }
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, [navigate]);

  // DARK MODE
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add("dark");
      localStorage.setItem("theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("theme", "light");
    }
  }, [darkMode]);

  return (
    <div className="min-h-screen flex flex-col bg-white dark:bg-gray-900 text-black dark:text-white">

      {/* HEADER */}
      <header className="fixed top-0 left-0 right-0 h-16 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 px-6 flex justify-between items-center z-20">

        {/* LEFT */}
        <div className="flex items-center gap-4">
          <button
            className="rounded-md hover:bg-emerald-500/10 dark:hover:bg-emerald-500/20 cursor-pointer p-2"
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            <Menu />
          </button>
          <h1 
            className="text-2xl font-bold text-emerald-600 cursor-pointer"
            onClick={() => navigate("/feed")}
          >
            SkillSwap
          </h1>
        </div>

        {/* SEARCH */}
        <div className="flex items-center justify-center flex-1 px-4">
          <div className="relative w-full max-w-md">
            <input
              type="text"
              placeholder="Search..."
              className="w-full rounded-full border border-gray-300 dark:border-gray-700 bg-gray-100 dark:bg-gray-800 px-4 py-2 pl-10 text-base"
            />
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 dark:text-gray-300" size={20} />
          </div>
        </div>

        {/* PROFILE + MENU */}
        <div className="relative flex items-center gap-4">
          <img
            src={profile?.avatar_url || `https://ui-avatars.com/api/?name=${encodeURIComponent(profile?.full_name || profile?.username || 'User')}&background=10b981&color=fff`}
            alt="Profile"
            className="w-10 h-10 rounded-full cursor-pointer border border-gray-300 dark:border-gray-700 object-cover"
            onClick={() => setSettingsOpen(!settingsOpen)}
          />

          {/* Dropdown */}
          <div
            className={`
              absolute right-0 top-14 w-48 p-2 rounded-lg shadow-xl
              bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700
              transform transition-all duration-200 origin-top-right
              ${settingsOpen
                ? "opacity-100 scale-100 translate-y-0"
                : "opacity-0 scale-95 -translate-y-2 pointer-events-none"}
            `}
          >
            <button className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md cursor-pointer">
              Profile Settings
            </button>
            <button className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md cursor-pointer">
              Account
            </button>
            <button className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md cursor-pointer">
              Help Center
            </button>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT WRAPPER */}
      <div className="flex flex-1 mt-16">
        {/* SIDEBAR */}
        <aside
          className={`
            fixed top-16 left-0 h-[calc(100vh-4rem)]
            bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800
            flex flex-col justify-between z-10 transition-all duration-300
            ${sidebarOpen ? "w-64 p-4" : "w-16 p-2"}
          `}
        >
          <div className="flex flex-col gap-2">
            <SidebarButton icon={<Menu />} text="Toggle" sidebarOpen={sidebarOpen} onClick={() => setSidebarOpen(!sidebarOpen)} hidden={true} />
            <SidebarButton icon={<Home />} text="Feed" sidebarOpen={sidebarOpen} onClick={() => navigate("/feed")} />
            <SidebarButton icon={<Users />} text="Friends" sidebarOpen={sidebarOpen} />
            <SidebarButton icon={<Mail />} text="Messages" sidebarOpen={sidebarOpen} />
            <SidebarButton icon={<Bell />} text="Notifications" sidebarOpen={sidebarOpen} />
          </div>

          <div>
            <SidebarButton 
              icon={<LogOut />} 
              text="Logout" 
              sidebarOpen={sidebarOpen}
              onClick={() => {
                localStorage.removeItem("token");
                localStorage.removeItem("user");
                localStorage.removeItem("refresh_token");
                navigate("/login");
              }}
            />
          </div>
        </aside>

        {/* MAIN PROFILE CONTENT */}
        <main
          className={`flex-1 p-6 transition-all duration-300 overflow-y-auto
            ${sidebarOpen ? "ml-64" : "ml-16"}`}
        >
          {/* Loading State */}
          {loading && (
            <div className="max-w-4xl mx-auto text-center py-20">
              <p className="text-gray-500 dark:text-gray-400 text-lg">Loading profile...</p>
            </div>
          )}

          {/* Error State */}
          {error && !loading && (
            <div className="max-w-4xl mx-auto">
              <div className="p-6 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <p className="text-red-800 dark:text-red-200">{error}</p>
              </div>
            </div>
          )}

          {/* Profile Content */}
          {!loading && !error && profile && (
          <div className="max-w-4xl mx-auto">
            {/* Cover Image */}
            <div className="relative h-48 bg-linear-to-r from-emerald-500 to-teal-600 rounded-xl mb-20">
              <button className="absolute top-4 right-4 p-2 bg-white dark:bg-gray-800 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition cursor-pointer">
                <Camera size={20} className="text-gray-700 dark:text-gray-300" />
              </button>

              {/* Profile Picture */}
              <div className="absolute -bottom-16 left-8">
                <div className="relative">
                  <img
                    src={profile?.avatar_url || `https://ui-avatars.com/api/?name=${encodeURIComponent(profile?.full_name || profile?.username)}&background=10b981&color=fff&size=150`}
                    alt="Profile"
                    className="w-32 h-32 rounded-full border-4 border-white dark:border-gray-900 object-cover"
                  />
                  <button className="absolute bottom-2 right-2 p-2 bg-emerald-500 rounded-full hover:bg-emerald-600 transition cursor-pointer">
                    <Camera size={16} className="text-white" />
                  </button>
                </div>
              </div>
            </div>

            {/* Profile Info */}
            <div className="px-8">
              <div className="flex justify-between items-start mb-6">
                <div>
                  <h2 className="text-3xl font-bold">{profile?.full_name || profile?.username}</h2>
                  <p className="text-gray-500 dark:text-gray-400">@{profile?.username}</p>
                </div>
                <button
                  onClick={() => setIsEditing(!isEditing)}
                  className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg transition cursor-pointer"
                >
                  <Edit size={18} />
                  {isEditing ? "Save Profile" : "Edit Profile"}
                </button>
              </div>

              {/* Bio */}
              <p className="text-gray-700 dark:text-gray-300 mb-4">
                {profile?.role ? `Role: ${profile.role}` : "SkillSwap Member"}
              </p>

              {/* Meta Info */}
              <div className="flex flex-wrap gap-4 text-sm text-gray-600 dark:text-gray-400 mb-6">
                <div className="flex items-center gap-2">
                  <Calendar size={16} />
                  <span>Joined {new Date(profile?.created_at).toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}</span>
                </div>
              </div>

              {/* Stats */}
              <div className="flex gap-8 mb-8 pb-6 border-b border-gray-200 dark:border-gray-800">
                <div className="text-center">
                  <p className="text-2xl font-bold text-emerald-600">0</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Posts</p>
                </div>
                <div className="text-center cursor-pointer hover:opacity-80 transition">
                  <p className="text-2xl font-bold text-emerald-600">0</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Followers</p>
                </div>
                <div className="text-center cursor-pointer hover:opacity-80 transition">
                  <p className="text-2xl font-bold text-emerald-600">0</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Following</p>
                </div>
              </div>

              {/* Skills Section */}
              <div className="mb-8">
                <div className="flex items-center gap-2 mb-4">
                  <Award className="text-emerald-500" size={20} />
                  <h3 className="text-xl font-bold">Profile Info</h3>
                </div>
                <div className="space-y-2">
                  <p className="text-gray-700 dark:text-gray-300">
                    <strong>Username:</strong> {profile?.username}
                  </p>
                  <p className="text-gray-700 dark:text-gray-300">
                    <strong>Full Name:</strong> {profile?.full_name || 'Not set'}
                  </p>
                  <p className="text-gray-700 dark:text-gray-300">
                    <strong>Role:</strong> {profile?.role || 'user'}
                  </p>
                </div>
              </div>

              {/* Recent Activity */}
              <div>
                <h3 className="text-xl font-bold mb-4">Recent Activity</h3>
                <div className="p-6 bg-white dark:bg-gray-800 rounded-xl shadow border border-gray-200 dark:border-gray-700 text-center">
                  <p className="text-gray-500 dark:text-gray-400">
                    No recent activity yet. Start exploring and connecting with others!
                  </p>
                </div>
              </div>
            </div>
          </div>
          )}
        </main>
      </div>

      {/* FOOTER */}
      <footer
        id="contact"
        className="py-4 bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-800"
      >
        <div className="max-w-7xl mx-auto px-6 text-center">
          <p className="text-sm text-gray-600 dark:text-gray-400">
            © {new Date().getFullYear()} SkillSwap. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}

/* SIDEBAR BUTTON */
function SidebarButton({ icon, text, sidebarOpen, onClick, hidden }) {
  if (hidden) return null;
  return (
    <button
      onClick={onClick}
      className={`
        flex items-center py-3 w-full rounded-md transition-colors duration-300 
        hover:bg-emerald-500/10 dark:hover:bg-emerald-500/20 cursor-pointer
        ${sidebarOpen ? "gap-4 px-4" : "justify-center"}
      `}
    >
      {icon}
      {sidebarOpen && <span className="font-medium">{text}</span>}
    </button>
  );
}