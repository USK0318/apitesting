// src/components/Profile.js
import React, { useEffect, useState } from 'react';
import API from '../services/api';
import { Link } from 'react-router-dom';
import './Profile.css'; // Import the CSS file

const Profile = () => {
    const [userData, setUserData] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const res = await API.get('/me');
                setUserData(res.data);
            } catch (err) {
                console.error('Error fetching profile:', err);
                setError(err.response.data.message);
            }
        };

        fetchData();
    }, []);

    if (error) {
        if (error === 'Access token is missing') {
            window.location.href = '/';
            return null;
        }
        return <p className="error-message">{error}</p>;
    }

    if (!userData) {
        return <p>Loading...</p>;
    }

    return (
        <div className="profile-container">
            <h2>User Profile</h2>
            <p><strong>Email:</strong> {userData.email}</p>
            <p><strong>Name:</strong> {userData.name}</p>
            <p><strong>Phone:</strong> {userData.phone}</p>

            <Link to="/logout">
                <button>Logout</button>
            </Link>
        </div>
    );
};

export default Profile;
