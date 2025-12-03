const API_URL = "http://localhost:4000/api/users";
const AUTH_URL = "http://localhost:4000/auth";

// Register user (Supabase)
export const registerUser = async (username, email, password, full_name) => {
  const response = await fetch(`${AUTH_URL}/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, email, password, full_name }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Registration failed");
  }

  return response.json();
};

// Login user (Supabase)
export const loginUser = async (email, password) => {
  const response = await fetch(`${AUTH_URL}/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Login failed");
  }

  return response.json();
};

// Get all users
export const getAllUsers = async () => {
  const token = localStorage.getItem("token");
  
  const response = await fetch(API_URL, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: token ? `Bearer ${token}` : "",
    },
  });

  if (!response.ok) {
    throw new Error("Failed to fetch users");
  }

  return response.json();
};

// Get all profiles (Supabase)
export const getAllProfiles = async () => {
  const response = await fetch("http://localhost:4000/api/profiles", {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    throw new Error("Failed to fetch profiles");
  }

  const data = await response.json();
  return data.profiles || [];
};

// Get current user profile
export const getCurrentUserProfile = async () => {
  const token = localStorage.getItem("token");
  
  if (!token) {
    throw new Error("No authentication token found");
  }

  const response = await fetch("http://localhost:4000/auth/profile", {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to fetch profile");
  }

  const data = await response.json();
  return data.profile;
};
