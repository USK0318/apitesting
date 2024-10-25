// src/components/Logout.js
import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const Logout = () => {
    const navigate = useNavigate();

    useEffect(() => {
        // Call the logout API
        axios.post('http://localhost:8001/api/logout', {}, { withCredentials: true })
            .then(response => {
                if (response.status === 200) {
                    // On successful logout, redirect to login page
                    navigate('/');
                } else {
                    console.error('Logout failed');
                }
            })
            .catch(error => {
                console.error('Error during logout:', error);
            });
    }, [navigate]);

    return <div>Logging out...</div>;
};

export default Logout;
