import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Menu, Search, Users, LogOut, Send, Bell, Mail, ArrowLeft } from "lucide-react";

export default function ChatPage() {
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [darkMode] = useState(localStorage.getItem("theme") === "dark");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selectedChat, setSelectedChat] = useState(null);
  const [messageInput, setMessageInput] = useState("");

  const [chats] = useState(
    [...Array(8)].map((_, i) => ({
      id: i,
      name: `User ${i + 20}`,
      lastMessage: `Hey! This is the last message from conversation ${i + 1}`,
      time: `${i + 1}h ago`,
      unread: i % 3 === 0 ? i + 1 : 0,
      avatar: `https://i.pravatar.cc/40?img=${i + 20}`
    }))
  );

  const [messages, setMessages] = useState([
    { id: 1, sender: "them", text: "Hey! How are you?", time: "10:30 AM" },
    { id: 2, sender: "me", text: "I'm doing great! How about you?", time: "10:32 AM" },
    { id: 3, sender: "them", text: "Pretty good! Want to exchange skills?", time: "10:33 AM" },
    { id: 4, sender: "me", text: "Sure! What skills are you interested in?", time: "10:35 AM" },
  ]);

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add("dark");
      localStorage.setItem("theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("theme", "light");
    }
  }, [darkMode]);

  const handleSendMessage = () => {
    if (messageInput.trim() && selectedChat !== null) {
      setMessages([
        ...messages,
        {
          id: messages.length + 1,
          sender: "me",
          text: messageInput,
          time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
        }
      ]);
      setMessageInput("");
    }
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
              placeholder="Search messages..."
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
            bg-gray-800 dark:bg-gray-950 border-r border-gray-700 dark:border-gray-900
            flex flex-col justify-between z-20 transition-all duration-300
            ${sidebarOpen ? "w-64 p-4" : "w-16 p-2"}
          `}
        >
          <div className="flex flex-col gap-1">
            <SidebarButton icon={<Menu />} text="Toggle" sidebarOpen={sidebarOpen} onClick={() => setSidebarOpen(!sidebarOpen)} hidden={true} />
            <SidebarButton icon={<ArrowLeft />} text="Back to Feed" sidebarOpen={sidebarOpen} onClick={() => navigate("/feed")} />
            <SidebarButton icon={<Users />} text="Friends" sidebarOpen={sidebarOpen} />
            <SidebarButton icon={<Mail />} text="Chats" sidebarOpen={sidebarOpen} onClick={() => navigate("/chat")} />
            <SidebarButton icon={<Bell />} text="Status" sidebarOpen={sidebarOpen} />
          </div>

          <div className="flex flex-col gap-1">
            <SidebarButton
              icon={<LogOut />}
              text="Logout"
              sidebarOpen={sidebarOpen}
              onClick={() => navigate("/login")}
            />
          </div>
        </aside>

        {/* CHAT LIST */}
        <aside
          className={`fixed top-16 h-[calc(100vh-4rem)] w-96 bg-gray-900 dark:bg-gray-900 border-r border-gray-700 dark:border-gray-800 overflow-y-auto transition-all duration-300 z-10
            ${sidebarOpen ? "left-64" : "left-16"}`}
        >
          <div className="p-3">
            <h2 className="text-xl font-bold mb-3 text-white px-2">Chats</h2>
            <div className="space-y-0">
              {chats.map((chat) => (
                <div
                  key={chat.id}
                  onClick={() => setSelectedChat(chat.id)}
                  className={`p-3 cursor-pointer transition-colors border-b border-gray-800 dark:border-gray-800 ${
                    selectedChat === chat.id
                      ? "bg-gray-800 dark:bg-gray-800"
                      : "hover:bg-gray-800 dark:hover:bg-gray-800"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <img
                      src={chat.avatar}
                      alt={chat.name}
                      className="w-12 h-12 rounded-full"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <h3 className="font-semibold text-sm text-white">{chat.name}</h3>
                        <span className="text-xs text-gray-400">{chat.time}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <p className="text-sm text-gray-400 truncate flex-1">{chat.lastMessage}</p>
                        {chat.unread > 0 && (
                          <span className="ml-2 flex-shrink-0 w-5 h-5 flex items-center justify-center text-xs bg-emerald-500 text-white rounded-full">
                            {chat.unread}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* CHAT WINDOW */}
        <main
          className={`flex-1 flex flex-col transition-all duration-300 ${sidebarOpen ? "ml-160" : "ml-112"} mr-0`}
        >
          {selectedChat !== null ? (
            <>
              {/* Chat Header */}
             <div className="h-16 bg-red-800 dark:bg-gray-800 border-b border-gray-700 dark:border-gray-700 px-6 flex items-center gap-4">
                <img
                  src={chats[selectedChat]?.avatar}
                  alt={chats[selectedChat]?.name}
                  className="w-10 h-10 rounded-full"
                />
                <div>
                  <h3 className="font-semibold text-white">{chats[selectedChat]?.name}</h3>
                  <span className="text-xs text-gray-400">Active now</span>
                </div>
              </div>

              {/* Messages */}
              <div className="flex-1 overflow-y-auto p-6 space-y-3 bg-gray-900 dark:bg-gray-950">
                {messages.map((message) => (
                  <div
                    key={message.id}
                    className={`flex ${message.sender === "me" ? "justify-end" : "justify-start"}`}
                  >
                    <div
                      className={`max-w-md px-4 py-2 rounded-lg ${
                        message.sender === "me"
                          ? "bg-emerald-600 text-white rounded-br-none"
                          : "bg-gray-800 text-white rounded-bl-none"
                      }`}
                    >
                      <p className="text-sm">{message.text}</p>
                      <span className={`text-xs block text-right mt-1 ${message.sender === "me" ? "text-emerald-100" : "text-gray-400"}`}>
                        {message.time}
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Message Input */}
              <div className="h-16 bg-gray-800 dark:bg-gray-800 border-t border-gray-700 dark:border-gray-700 px-6 flex items-center gap-3">
                <input
                  type="text"
                  placeholder="Type a message..."
                  value={messageInput}
                  onChange={(e) => setMessageInput(e.target.value)}
                  onKeyPress={(e) => e.key === "Enter" && handleSendMessage()}
                  className="flex-1 rounded-lg border-0 bg-gray-700 dark:bg-gray-900 text-white placeholder-gray-400 px-4 py-2 focus:outline-none focus:ring-2 focus:ring-emerald-500"
                />
                <button
                  onClick={handleSendMessage}
                  className="p-2 rounded-full bg-emerald-600 text-white hover:bg-emerald-700 transition cursor-pointer"
                >
                  <Send size={20} />
                </button>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center bg-gray-900 dark:bg-gray-950">
              <div className="text-center">
                <Mail size={64} className="mx-auto mb-4 text-gray-600 dark:text-gray-700" />
                <h2 className="text-2xl font-bold mb-2 text-white">Select a conversation</h2>
                <p className="text-gray-400">Choose a chat from the list to start messaging</p>
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
        hover:bg-gray-700 dark:hover:bg-gray-800 cursor-pointer text-gray-300
        ${sidebarOpen ? "gap-4 px-4" : "justify-center"}
      `}
    >
      {icon}
      {sidebarOpen && <span className="font-medium">{text}</span>}
    </button>
  );
}
