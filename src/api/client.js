import axios from "axios";
import { API_URL } from "../utils/constants";
import { showToast } from "../utils/toast";

// Auth token management
export const setAuthToken = (token) => {
  if (token) {
    localStorage.setItem("token", token);
    axios.defaults.headers.common["Authorization"] = `Bearer ${token}`;
  } else {
    localStorage.removeItem("token");
    delete axios.defaults.headers.common["Authorization"];
  }
};

export const getStoredToken = () => localStorage.getItem("token");

// Auto-logout on 401, rate limit handling on 429
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      if (localStorage.getItem("token")) {
        localStorage.removeItem("token");
        delete axios.defaults.headers.common["Authorization"];
        window.location.href = "/";
      }
    } else if (error.response?.status === 429) {
      const retryAfter = error.response?.data?.retry_after || error.response?.headers?.["retry-after"];
      const parsed = retryAfter ? parseInt(retryAfter, 10) : null;
      const seconds = parsed && !isNaN(parsed) ? Math.max(1, parsed) : null;
      const message = seconds
        ? `Too many requests. Please try again in ${seconds} seconds.`
        : "Too many requests. Please try again shortly.";
      showToast(message, "warning");
    }
    return Promise.reject(error);
  }
);

// Auth
export const login = async (identifier, password) => {
  const response = await axios.post(`${API_URL}/auth/login`, { identifier, password });
  return response.data;
};

export const signup = async (email, username, password) => {
  const response = await axios.post(`${API_URL}/auth/signup`, {
    email,
    username,
    password,
  });
  return response.data;
};

export const checkUsername = async (username) => {
  const response = await axios.get(`${API_URL}/auth/check-username`, {
    params: { username }
  });
  return response.data;
};

export const verifyEmail = async (email, code) => {
  const response = await axios.post(`${API_URL}/auth/verify-email`, { email, code });
  return response.data;
};

export const resendVerificationCode = async (email) => {
  const response = await axios.post(`${API_URL}/auth/resend-code`, { email });
  return response.data;
};

export const forgotPassword = async (email) => {
  const response = await axios.post(`${API_URL}/auth/forgot-password`, { email });
  return response.data;
};

export const resetPassword = async (email, code, newPassword) => {
  const response = await axios.post(`${API_URL}/auth/reset-password`, {
    email,
    code,
    new_password: newPassword
  });
  return response.data;
};

export const getMe = async () => {
  const response = await axios.get(`${API_URL}/auth/me`);
  return response.data;
};

export const logout = async () => {
  try {
    await axios.post(`${API_URL}/auth/logout`);
  } catch {
    // Fire-and-forget
  }
};

export const changePassword = async (currentPassword, newPassword) => {
  const response = await axios.put(`${API_URL}/auth/change-password`, {
    current_password: currentPassword,
    new_password: newPassword
  });
  return response.data;
};

export const deleteAccount = async (password) => {
  const response = await axios.post(`${API_URL}/auth/delete-account`, { password });
  return response.data;
};
