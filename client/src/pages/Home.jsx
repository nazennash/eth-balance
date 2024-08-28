import React, { useEffect, useState } from 'react';
import useAuth from '../hooks/useAuth';
import useUser from '../hooks/useUser';
import { axiosPrivateInstance } from '../api/apiConfig';

export default function Home() {
    const { user } = useAuth();
    const getUser = useUser();
    const [balance, setBalance] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        getUser();

        async function fetchBalance() {
            if (user?.email) {
                try {
                    const response = await axiosPrivateInstance.get('auth/wallet/balance/');
                    setBalance(response.data.balance);
                    console.log("Balance:", response.data.balance);
                } catch (err) {
                    setError('Error fetching balance');
                    console.error("Error fetching balance:", err);
                } finally {
                    setLoading(false);
                }
            }
        }

        fetchBalance();
    }, [user]);

    return (
        <div className='container mt-3'>
            <h2>
                <div className='row'>
                    <div className="mb-12">
                        {user?.email !== undefined ? (
                            loading ? (
                                <p>Loading wallet balance...</p>
                            ) : error ? (
                                <p>{error}</p>
                            ) : (
                                <p>Your Ethereum wallet balance: {balance} ETH</p>
                            )
                        ) : (
                            'Please login first'
                        )}
                    </div>
                </div>
            </h2>
        </div>
    );
}
