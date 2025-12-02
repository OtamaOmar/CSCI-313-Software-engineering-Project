import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Menu, Search, Users, LogOut, Heart, MessageCircle, Share2, Plus, Mail, Bell, Home } from "lucide-react";

export default function FeedPage() {
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [darkMode] = useState(localStorage.getItem("theme") === "dark");
  const [settingsOpen, setSettingsOpen] = useState(false);

  const [posts, setPosts] = useState(
    [...Array(10)].map((_, i) => ({
      id: i,
      content: `This is some sample feed content for post #${i + 1}.`,
      likes: 12,
      comments: 4,
      shares: 2
    }))
  );

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

  // REACTIONS HANDLER
  const handleReaction = (postId, type) => {
    setPosts(prev =>
      prev.map(post => {
        if (post.id === postId) {
          if (type === "like") return { ...post, likes: post.likes + 1 };
          if (type === "comment") return { ...post, comments: post.comments + 1 };
          if (type === "share") return { ...post, shares: post.shares + 1 };
        }
        return post;
      })
    );
  };

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
          <h1 className="text-2xl font-bold text-emerald-600">SkillSwap</h1>
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
            src="https://i.pravatar.cc/40"
            alt="Profile"
            className="w-10 h-10 rounded-full cursor-pointer border border-gray-300 dark:border-gray-700"
            onClick={() => navigate("/profile")}
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
              onClick={() => navigate("/login")}
            />
          </div>
        </aside>

        {/* MAIN FEED */}
        <main
          className={`flex-1 p-6 transition-all duration-300 overflow-y-auto
            ${sidebarOpen ? "ml-64" : "ml-16"} mr-80`}
        >
          <h2 className="text-3xl font-bold mb-6">Your Feed</h2>

          <div className="space-y-6">
            {posts.map(post => (
              <div
                key={post.id}
                className="relative p-6 bg-white dark:bg-gray-800 rounded-xl shadow border border-gray-200 dark:border-gray-700"
              >
                {/* HEADER */}
                <div className="flex items-center gap-4 mb-3">
                  <img
                    src={`https://i.pravatar.cc/40?img=${post.id + 1}`}
                    className="w-10 h-10 rounded-full border border-gray-300 dark:border-gray-700"
                  />
                  <div>
                    <h3 className="font-semibold">User {post.id + 1}</h3>
                    <span className="text-sm text-gray-500 dark:text-gray-400">Nov {post.id + 5}, 2025</span>
                  </div>
                </div>

                {/* CONTENT */}
                <p className="mt-2">{post.content}</p>

                {/* REACTIONS */}
                <div className="flex items-center gap-6 mt-4 text-gray-500 dark:text-gray-400">
                  <button onClick={() => handleReaction(post.id, "like")} className="flex items-center gap-1 hover:text-emerald-500 cursor-pointer">
                    <Heart size={18} /> {post.likes}
                  </button>
                  <button onClick={() => handleReaction(post.id, "comment")} className="flex items-center gap-1 hover:text-emerald-500 cursor-pointer">
                    <MessageCircle size={18} /> {post.comments}
                  </button>
                  <button onClick={() => handleReaction(post.id, "share")} className="flex items-center gap-1 hover:text-emerald-500 cursor-pointer">
                    <Share2 size={18} /> {post.shares}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </main>

        {/* RIGHT SIDEBAR */}
        <aside className="fixed top-16 right-0 h-[calc(100vh-4rem)] w-80 bg-white dark:bg-gray-950 border-l border-gray-200 dark:border-gray-900 p-4 flex flex-col">
          <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4">Friend Suggestions</h3>
          
          <div className="space-y-3 overflow-y-auto">
            {[...Array(8)].map((_, i) => (
              <div key={i} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                <div className="flex items-center gap-3 flex-1">
                  <img
                    src={`https://i.pravatar.cc/40?img=${i + 20}`}
                    className="w-10 h-10 rounded-full border border-emerald-500"
                  />
                  <div className="flex-1">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white">User {i + 20}</h4>
                    <p className="text-xs text-gray-600 dark:text-gray-400">3 mutual friends</p>
                  </div>
                </div>
                <button className="p-1.5 rounded-full hover:bg-emerald-500/20 text-emerald-500 transition cursor-pointer">
                  <Plus size={18} />
                </button>
              </div>
            ))}
          </div>
        </aside>
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