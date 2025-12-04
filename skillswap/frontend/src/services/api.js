import axios from "axios";

const BASE_URL = "http://localhost:4000";
const API_URL = `${BASE_URL}/api`;
const AUTH_URL = `${BASE_URL}/api/auth`;

// Create axios instance
const axiosInstance = axios.create({
  baseURL: BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Add interceptor to include token in headers
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle token refresh
axiosInstance.interceptors.response.use(
  (response) => {
    // Ensure response data is properly formatted
    if (!response.data) {
      return Promise.reject(new Error("Empty response from server"));
    }
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = localStorage.getItem("refreshToken");
        if (!refreshToken) {
          localStorage.removeItem("token");
          localStorage.removeItem("refreshToken");
          window.location.href = "/login";
          return Promise.reject(error);
        }

        const response = await axios.post(`${AUTH_URL}/refresh`, {
          refresh_token: refreshToken,
        });

        const session = response.data?.session;
        if (session?.access_token) {
          localStorage.setItem("token", session.access_token);
        }
        if (session?.refresh_token) {
          localStorage.setItem("refreshToken", session.refresh_token);
        }

        // Retry original request with new token
        originalRequest.headers.Authorization = `Bearer ${session.access_token}`;
        return axiosInstance(originalRequest);
      } catch (refreshError) {
        localStorage.removeItem("token");
        localStorage.removeItem("refreshToken");
        window.location.href = "/login";
        return Promise.reject(refreshError);
      }
    }

    // Better error logging for debugging
    if (error.response?.data?.error) {
      return Promise.reject(new Error(error.response.data.error));
    }

    return Promise.reject(error);
  }
);

// Register user (Supabase)
export const registerUser = async (username, email, password, full_name) => {
  try {
    const response = await axios.post(`${AUTH_URL}/signup`, {
      username,
      email,
      password,
      full_name,
    });

    const data = response.data;

    // Store both access and refresh tokens
    if (data.session?.access_token) {
      localStorage.setItem("token", data.session.access_token);
    }
    if (data.session?.refresh_token) {
      localStorage.setItem("refreshToken", data.session.refresh_token);
    }

    return data;
  } catch (err) {
    const errorMessage = err.response?.data?.error || "Registration failed";
    throw new Error(errorMessage);
  }
};

// Login user (Supabase)
export const loginUser = async (email, password) => {
  try {
    const response = await axios.post(`${AUTH_URL}/login`, {
      email,
      password,
    });

    const data = response.data;

    // Store both access and refresh tokens
    if (data.session?.access_token) {
      localStorage.setItem("token", data.session.access_token);
    }
    if (data.session?.refresh_token) {
      localStorage.setItem("refreshToken", data.session.refresh_token);
    }

    return data;
  } catch (err) {
    const errorMessage = err.response?.data?.error || "Login failed";
    throw new Error(errorMessage);
  }
};

// Get all users
export const getAllUsers = async () => {
  try {
    const response = await axiosInstance.get(`${API_URL}/users`);
    return response.data;
  } catch (err) {
    const errorMessage = err.response?.data?.error || "Failed to fetch users";
    throw new Error(errorMessage);
  }
};

// Get all profiles
export const getAllProfiles = async () => {
  try {
    const response = await axiosInstance.get(`${API_URL}/users`);
    return Array.isArray(response.data) ? response.data : [];
  } catch (err) {
    console.error("getAllProfiles error:", err);
    const errorMessage = err.response?.data?.error || "Failed to fetch profiles";
    throw new Error(errorMessage);
  }
};

// Get current user profile
export const getCurrentUserProfile = async () => {
  try {
    const token = localStorage.getItem("token");
    if (!token) {
      throw new Error("No authentication token found");
    }

    const response = await axiosInstance.get(`${API_URL}/users/me`);
    return response.data;
  } catch (err) {
    console.error("getCurrentUserProfile error:", err);
    const errorMessage = err.response?.data?.error || err.message || "Failed to fetch profile";
    throw new Error(errorMessage);
  }
};

// Logout user
export const logoutUser = async () => {
  try {
    await axiosInstance.post(`${AUTH_URL}/logout`);
  } catch (err) {
    console.error("Logout error:", err);
  } finally {
    localStorage.removeItem("token");
    localStorage.removeItem("refreshToken");
  }
};

// Check if user is authenticated
export const isAuthenticated = () => {
  const token = localStorage.getItem("token");
  return !!token;
};

// USER API OBJECT
export const userAPI = {
  getMe: async () => {
    const response = await axiosInstance.get(`${API_URL}/users/me`);
    return response.data;
  },

  getUser: async (userId) => {
    const response = await axiosInstance.get(`${API_URL}/users/${userId}`);
    return response.data;
  },

  getAllUsers: async () => {
    const response = await axiosInstance.get(`${API_URL}/users`);
    return response.data;
  },

  updateProfile: async (profileData) => {
    const response = await axiosInstance.put(`${API_URL}/users/me`, profileData);
    return response.data;
  },

  getUserPosts: async (userId) => {
    const response = await axiosInstance.get(`${API_URL}/posts/user/${userId}`);
    return response.data;
  },

  uploadProfilePicture: async (file) => {
    const formData = new FormData();
    formData.append("profile_picture", file);
    const response = await axiosInstance.post(`${API_URL}/users/upload/profile-picture`, formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return response.data;
  },

  uploadCoverImage: async (file) => {
    const formData = new FormData();
    formData.append("cover_image", file);
    const response = await axiosInstance.post(`${API_URL}/users/upload/cover-image`, formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return response.data;
  },
};

// POST API OBJECT
export const postAPI = {
  getAllPosts: async () => {
    const response = await axiosInstance.get(`${API_URL}/posts`);
    return response.data;
  },

  getUserPosts: async (userId) => {
    const response = await axiosInstance.get(`${API_URL}/posts/user/${userId}`);
    return response.data;
  },

  createPost: async (content, image_url = null) => {
    const response = await axiosInstance.post(`${API_URL}/posts`, {
      content,
      image_url,
    });
    return response.data;
  },

  getComments: async (postId) => {
    const response = await axiosInstance.get(`${API_URL}/posts/${postId}/comments`);
    return response.data;
  },

  addComment: async (postId, content) => {
    const response = await axiosInstance.post(`${API_URL}/posts/${postId}/comment`, {
      content,
    });
    return response.data;
  },

  likePost: async (postId) => {
    const response = await axiosInstance.post(`${API_URL}/posts/${postId}/like`);
    return response.data;
  },

  unlikePost: async (postId) => {
    const response = await axiosInstance.delete(`${API_URL}/posts/${postId}/like`);
    return response.data;
  },
};

// SKILLS API OBJECT
export const skillsAPI = {
  getMySkills: async () => {
    const response = await axiosInstance.get(`${API_URL}/skills/me`);
    return response.data;
  },

  getUserSkills: async (userId) => {
    const response = await axiosInstance.get(`${API_URL}/skills/user/${userId}`);
    return response.data;
  },

  addSkill: async (skillName, skillType) => {
    const response = await axiosInstance.post(`${API_URL}/skills`, {
      skill_name: skillName,
      skill_type: skillType,
    });
    return response.data;
  },

  updateSkill: async (skillId, skillName, skillType) => {
    const response = await axiosInstance.put(`${API_URL}/skills/${skillId}`, {
      skill_name: skillName,
      skill_type: skillType,
    });
    return response.data;
  },

  deleteSkill: async (skillId) => {
    const response = await axiosInstance.delete(`${API_URL}/skills/${skillId}`);
    return response.data;
  },
};

// FRIENDSHIPS API OBJECT
export const friendshipsAPI = {
  getMyFriendships: async () => {
    const response = await axiosInstance.get(`${API_URL}/friendships`);
    return response.data;
  },

  sendFriendRequest: async (friendId) => {
    const response = await axiosInstance.post(`${API_URL}/friendships/request`, {
      friend_id: friendId,
    });
    return response.data;
  },

  acceptFriendRequest: async (friendshipId) => {
    const response = await axiosInstance.put(`${API_URL}/friendships/${friendshipId}/accept`);
    return response.data;
  },

  rejectFriendRequest: async (friendshipId) => {
    const response = await axiosInstance.delete(`${API_URL}/friendships/${friendshipId}/reject`);
    return response.data;
  },

  unfriend: async (friendId) => {
    const response = await axiosInstance.delete(`${API_URL}/friendships/${friendId}`);
    return response.data;
  },
};

export default axiosInstance;
