// src/services/api.js
import axios from 'axios';
import Cookies from 'js-cookie';

const API = axios.create({
  baseURL: 'http://localhost:8001/api', // Replace with your backend URL
  withCredentials: true, // Ensure cookies are sent with each request
});

// Attach accessToken from cookies to every request (if available)
API.interceptors.request.use(
  (config) => {
    const accessToken = Cookies.get('accessToken');
    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Automatically refresh the token if accessToken expires
API.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const refreshToken = Cookies.get('refreshToken');
      if (refreshToken) {
        try {
          const res = await axios.post(
            'http://localhost:8001/api/token',
            {},
            { withCredentials: true }
          );
          // Cookies.set('accessToken', res.data.accessToken);
          Cookies.set('accessToken', res.data.accessToken, { sameSite: 'strict', secure: true });

          // Retry the original request
          error.config.headers.Authorization = `Bearer ${res.data.accessToken}`;
          return axios(error.config);
        } catch (refreshError) {
          console.error('Token refresh failed', refreshError);
        }
      }
    }
    return Promise.reject(error);
  }
);

export default API;
