import React, { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Menu, Search, Users, LogOut, Mail, Bell, Edit, Camera, MapPin, Calendar, Award, Home, Heart, MessageCircle, Share2, Send } from "lucide-react";
import { userAPI } from "../services/api";
import LoadingSpinner from "../components/LoadingSpinner";

export default function ProfilePage() {
  const navigate = useNavigate();
  const { id } = useParams(); // Get user ID from URL if viewing another user's profile
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [darkMode] = useState(localStorage.getItem("theme") === "dark");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [profile, setProfile] = useState(null);
  const [isOwnProfile, setIsOwnProfile] = useState(false);
  const [uploadingImage, setUploadingImage] = useState(false);
  const [uploadingCover, setUploadingCover] = useState(false);
  const [userPosts, setUserPosts] = useState([]);
  const [loadingPosts, setLoadingPosts] = useState(true);
  const [showAddSkill, setShowAddSkill] = useState(false);
  const [newSkill, setNewSkill] = useState("");
  const [proficiencyLevel, setProficiencyLevel] = useState("Intermediate");
  const [addingSkill, setAddingSkill] = useState(false);
  const fileInputRef = useRef(null);
  const coverInputRef = useRef(null);
  const [editForm, setEditForm] = useState({
    full_name: "",
    bio: "",
    location: "",
    country: ""
  });

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

  // Load profile data
  const loadProfile = useCallback(async () => {
    try {
      let userData;
      let userId;
      if (id) {
        // Viewing another user's profile
        userData = await userAPI.getUser(id);
        userId = id;
        setIsOwnProfile(false);
      } else {
        // Viewing own profile
        userData = await userAPI.getMe();
        userId = userData.id;
        setIsOwnProfile(true);
      }
      setProfile(userData);
      setEditForm({
        full_name: userData.full_name || "",
        bio: userData.bio || "",
        location: userData.location || "",
        country: userData.country || ""
      });

      // Load user posts
      loadUserPosts(userId);
    } catch (error) {
      console.error("Failed to load profile:", error);
      if (error.message.includes('token')) {
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  }, [id, navigate]);

  useEffect(() => {
    loadProfile();
  }, [loadProfile]);



  const loadUserPosts = async (userId) => {
    try {
      setLoadingPosts(true);
      const posts = await userAPI.getUserPosts(userId);
      setUserPosts(posts);
    } catch (error) {
      console.error("Failed to load user posts:", error);
      setUserPosts([]);
    } finally {
      setLoadingPosts(false);
    }
  };

  const handleSaveProfile = async () => {
    try {
      const updated = await userAPI.updateProfile(editForm);
      setProfile(updated);
      setIsEditing(false);
    } catch (error) {
      console.error("Failed to update profile:", error);
    }
  };

  const handleProfilePictureClick = () => {
    if (isOwnProfile && fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const handleImageUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Validate file size (5MB limit)
    if (file.size > 5 * 1024 * 1024) {
      alert("File size must be less than 5MB");
      return;
    }

    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
      alert("Only image files (JPEG, PNG, GIF, WebP) are allowed");
      return;
    }

    try {
      setUploadingImage(true);
      const result = await userAPI.uploadProfilePicture(file);
      setProfile(result.user);
      // Update localStorage
      const savedUser = JSON.parse(localStorage.getItem('user') || '{}');
      savedUser.profile_picture = result.user.profile_picture;
      localStorage.setItem('user', JSON.stringify(savedUser));
    } catch (error) {
      console.error("Failed to upload image:", error);
      alert("Failed to upload profile picture");
    } finally {
      setUploadingImage(false);
    }
  };

  const handleCoverClick = () => {
    if (isOwnProfile && coverInputRef.current) {
      coverInputRef.current.click();
    }
  };

  const handleCoverUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Validate file size (5MB limit)
    if (file.size > 5 * 1024 * 1024) {
      alert("File size must be less than 5MB");
      return;
    }

    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
      alert("Only image files (JPEG, PNG, GIF, WebP) are allowed");
      return;
    }

    try {
      setUploadingCover(true);
      const result = await userAPI.uploadCoverImage(file);
      setProfile(result.user);
    } catch (error) {
      console.error("Failed to upload cover:", error);
      alert("Failed to upload cover image");
    } finally {
      setUploadingCover(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("refreshToken");
    navigate('/login');
  };





  const handleAddSkill = async () => {
    if (!newSkill.trim()) return;

    try {
      setAddingSkill(true);
      await userAPI.addSkill(newSkill, proficiencyLevel);
      
      // Reload profile to get updated skills from database
      await loadProfile();
      
      setNewSkill("");
      setProficiencyLevel("Intermediate");
      setShowAddSkill(false);
    } catch (error) {
      console.error('Failed to add skill:', error);
      alert(error.message || 'Failed to add skill');
    } finally {
      setAddingSkill(false);
    }
  };

  const handleDeleteSkill = async (skillId) => {
    if (!confirm('Are you sure you want to delete this skill?')) return;

    try {
      await userAPI.deleteSkill(skillId);
      
      // Reload profile to get updated skills from database
      await loadProfile();
    } catch (error) {
      console.error('Failed to delete skill:', error);
      alert('Failed to delete skill');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-white dark:bg-gray-900">
        <LoadingSpinner size="xl" />
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-white dark:bg-gray-900">
        <div className="text-xl text-gray-600 dark:text-gray-400">Profile not found</div>
      </div>
    );
  }

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
            src={profile?.profile_picture ? `http://localhost:4000${profile.profile_picture}` : "https://i.pravatar.cc/40"}
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
              onClick={handleLogout}
            />
          </div>
        </aside>

        {/* MAIN PROFILE CONTENT */}
        <main
          className={`flex-1 p-6 transition-all duration-300 overflow-y-auto
            ${sidebarOpen ? "ml-64" : "ml-16"}`}
        >
          {/* PROFILE HEADER */}
          <div className="max-w-4xl mx-auto">
            {/* Cover Image */}
            <div 
              className="relative h-48 bg-linear-to-r from-emerald-500 to-teal-600 rounded-xl mb-20 overflow-hidden"
              style={{
                backgroundImage: profile.cover_image ? `url(http://localhost:4000${profile.cover_image})` : undefined,
                backgroundSize: 'cover',
                backgroundPosition: 'center'
              }}
            >
              {isOwnProfile && (
                <>
                  <input
                    ref={coverInputRef}
                    type="file"
                    accept="image/*"
                    onChange={handleCoverUpload}
                    className="hidden"
                  />
                  <button 
                    onClick={handleCoverClick}
                    disabled={uploadingCover}
                    className="absolute top-4 right-4 p-2 bg-white dark:bg-gray-800 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {uploadingCover ? (
                      <div className="w-5 h-5 border-2 border-gray-700 dark:border-gray-300 border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <Camera size={20} className="text-gray-700 dark:text-gray-300" />
                    )}
                  </button>
                </>
              )}

              {/* Profile Picture */}
              <div className="absolute -bottom-16 left-8">
                <div className="relative">
                  <img
                    src={profile.profile_picture ? `http://localhost:4000${profile.profile_picture}` : "https://i.pravatar.cc/150"}
                    alt="Profile"
                    className="w-32 h-32 rounded-full border-4 border-white dark:border-gray-900 object-cover"
                  />
                  {isOwnProfile && (
                    <>
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept="image/*"
                        onChange={handleImageUpload}
                        className="hidden"
                      />
                      <button 
                        onClick={handleProfilePictureClick}
                        disabled={uploadingImage}
                        className="absolute bottom-2 right-2 p-2 bg-emerald-500 rounded-full hover:bg-emerald-600 transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {uploadingImage ? (
                          <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        ) : (
                          <Camera size={16} className="text-white" />
                        )}
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* Profile Info */}
            <div className="px-8">
              <div className="flex justify-between items-start mb-6">
                <div className="flex-1">
                  {isEditing ? (
                    <input
                      type="text"
                      value={editForm.full_name}
                      onChange={(e) => setEditForm({...editForm, full_name: e.target.value})}
                      className="text-3xl font-bold bg-transparent border-b-2 border-emerald-500 focus:outline-none mb-2 w-full"
                      placeholder="Full Name"
                    />
                  ) : (
                    <h2 className="text-3xl font-bold">{profile.full_name || profile.username}</h2>
                  )}
                  <p className="text-gray-500 dark:text-gray-400">@{profile.username}</p>
                </div>
                {isOwnProfile && (
                  <button
                    onClick={isEditing ? handleSaveProfile : () => setIsEditing(true)}
                    className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg transition cursor-pointer"
                  >
                    <Edit size={18} />
                    {isEditing ? "Save Profile" : "Edit Profile"}
                  </button>
                )}
              </div>

              {/* Bio */}
              {isEditing ? (
                <textarea
                  value={editForm.bio}
                  onChange={(e) => setEditForm({...editForm, bio: e.target.value})}
                  className="w-full p-3 rounded-lg bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 focus:ring-2 focus:ring-emerald-500 focus:outline-none mb-4"
                  rows="3"
                  placeholder="Tell us about yourself..."
                />
              ) : (
                <p className="text-gray-700 dark:text-gray-300 mb-4">{profile.bio || "No bio yet"}</p>
              )}

              {/* Meta Info */}
              <div className="flex flex-wrap gap-4 text-sm text-gray-600 dark:text-gray-400 mb-6">
                <div className="flex items-center gap-2">
                  <MapPin size={16} />
                  {isEditing ? (
                    <input
                      type="text"
                      value={editForm.location}
                      onChange={(e) => setEditForm({...editForm, location: e.target.value})}
                      className="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded border border-gray-300 dark:border-gray-700 focus:ring-2 focus:ring-emerald-500 focus:outline-none"
                      placeholder="City, Country"
                    />
                  ) : (
                    <span>{profile.location || "Not specified"}</span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <Calendar size={16} />
                  <span>Joined {new Date(profile.created_at).toLocaleDateString('en-US', { month: 'long', year: 'numeric' })}</span>
                </div>
              </div>

              {/* Stats */}
              <div className="flex gap-8 mb-8 pb-6 border-b border-gray-200 dark:border-gray-800">
                <div className="text-center">
                  <p className="text-2xl font-bold text-emerald-600">{profile.stats?.posts || 0}</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Posts</p>
                </div>
                <div className="text-center cursor-pointer hover:opacity-80 transition">
                  <p className="text-2xl font-bold text-emerald-600">{profile.stats?.followers || 0}</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Followers</p>
                </div>
                <div className="text-center cursor-pointer hover:opacity-80 transition">
                  <p className="text-2xl font-bold text-emerald-600">{profile.stats?.following || 0}</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Following</p>
                </div>
              </div>

              {/* Skills Section */}
              <div className="mb-8">
                <div className="flex items-center gap-2 mb-4">
                  <Award className="text-emerald-500" size={20} />
                  <h3 className="text-xl font-bold">Skills</h3>
                </div>
                <div className="flex flex-wrap gap-2">
                  {profile.skills && profile.skills.length > 0 ? (
                    profile.skills.map((skill) => (
                      <div
                        key={skill.id}
                        className="px-4 py-2 bg-emerald-500/10 dark:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 rounded-full text-sm font-medium flex items-center gap-2"
                      >
                        {skill.skill_name}
                        {isOwnProfile && (
                          <button
                            onClick={() => handleDeleteSkill(skill.id)}
                            className="text-red-500 hover:text-red-600 transition"
                          >
                            ×
                          </button>
                        )}
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500 dark:text-gray-400 text-sm">No skills added yet</p>
                  )}
                  {isOwnProfile && (
                    <button 
                      onClick={() => setShowAddSkill(!showAddSkill)}
                      className="px-4 py-2 border-2 border-dashed border-gray-300 dark:border-gray-700 rounded-full text-sm font-medium hover:border-emerald-500 dark:hover:border-emerald-500 transition cursor-pointer"
                    >
                      + Add Skill
                    </button>
                  )}
                </div>

                {/* Add Skill Form */}
                {showAddSkill && isOwnProfile && (
                  <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <div className="space-y-3">
                      <input
                        type="text"
                        value={newSkill}
                        onChange={(e) => setNewSkill(e.target.value)}
                        placeholder="Enter skill name (e.g., JavaScript, Design, Photography)"
                        className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 focus:ring-2 focus:ring-emerald-500 focus:outline-none"
                      />
                      <select
                        value={proficiencyLevel}
                        onChange={(e) => setProficiencyLevel(e.target.value)}
                        className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 focus:ring-2 focus:ring-emerald-500 focus:outline-none"
                      >
                        <option value="Beginner">Beginner</option>
                        <option value="Intermediate">Intermediate</option>
                        <option value="Advanced">Advanced</option>
                        <option value="Expert">Expert</option>
                      </select>
                      <div className="flex gap-2">
                        <button
                          onClick={handleAddSkill}
                          disabled={addingSkill || !newSkill.trim()}
                          className="flex-1 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {addingSkill ? 'Adding...' : 'Add Skill'}
                        </button>
                        <button
                          onClick={() => {
                            setShowAddSkill(false);
                            setNewSkill("");
                            setProficiencyLevel("Intermediate");
                          }}
                          className="px-4 py-2 bg-gray-300 hover:bg-gray-400 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-lg transition"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Recent Posts */}
              <div>
                <h3 className="text-xl font-bold mb-4">Recent Posts</h3>
                {loadingPosts ? (
                  <div className="flex justify-center py-8">
                    <LoadingSpinner size="lg" />
                  </div>
                ) : userPosts.length > 0 ? (
                  <div className="space-y-4">
                    {userPosts.map((post) => (
                      <div
                        key={post.id}
                        className="p-6 bg-white dark:bg-gray-800 rounded-xl shadow border border-gray-200 dark:border-gray-700"
                      >
                        <div className="flex items-center gap-4 mb-3">
                          <img
                            src={post.profile_picture ? `http://localhost:4000${post.profile_picture}` : "https://i.pravatar.cc/40"}
                            className="w-10 h-10 rounded-full border border-gray-300 dark:border-gray-700 object-cover"
                            alt={post.username}
                          />
                          <div>
                            <h4 className="font-semibold">{post.full_name || post.username}</h4>
                            <span className="text-sm text-gray-500 dark:text-gray-400">
                              {new Date(post.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                            </span>
                          </div>
                        </div>
                        <p className="text-gray-700 dark:text-gray-300 mb-3">{post.content}</p>
                        {post.image_url && (
                          <img
                            src={`http://localhost:4000${post.image_url}`}
                            alt="Post"
                            className="w-full rounded-lg mb-3"
                          />
                        )}
                        <div className="flex items-center gap-6 text-gray-500 dark:text-gray-400 text-sm">
                          <button className="flex items-center gap-1 hover:text-red-500 transition">
                            <Heart size={18} fill={post.user_liked ? 'currentColor' : 'none'} /> 
                            <span>{post.likes_count || 0}</span>
                          </button>
                          <button className="flex items-center gap-1 hover:text-blue-500 transition">
                            <MessageCircle size={18} /> <span>{post.comments_count || 0}</span>
                          </button>
                          <button className="flex items-center gap-1 hover:text-green-500 transition">
                            <Share2 size={18} /> <span>{post.shares_count || 0}</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500 dark:text-gray-400 text-center py-8">No posts yet</p>
                )}
              </div>
            </div>
          </div>
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