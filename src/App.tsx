// import reactLogo from './assets/react.svg'
// import viteLogo from '/vite.svg'
import './App.css'
// import Users from "./components/users.tsx";
import Auth from "./components/auth.tsx";
import {useEffect, useState} from "react";
import {BACKEND_URL} from "./constants.ts";

interface User {
    username: string;
    count: number | null;
    loggedIn: boolean;
}
function App() {
    const [userData, setUserData] = useState<User>({ loggedIn: false, username: '', count: null });
    const [isLoadingUserData, setIsLoadingUserData] = useState(false);
    const [isProcessingCount, setIsProcessingCount] = useState(false);
    useEffect(() => {
        if (isLoadingUserData) {
            return;
        }
        setIsLoadingUserData(true);
        fetch(`${BACKEND_URL}/api/me`, { credentials: 'include' })
            .then((res) => {
                return res.json()
            })
            .then(data => {
                if (data.loggedIn) {
                    setUserData({
                        loggedIn: data.loggedIn,
                        username: data.username,
                        count: data.count,
                    });
                } else {
                    setUserData({ loggedIn: false, username: '', count: null });
                }
            }).catch(
                (error) => {
                    console.log('Failed to logIn', { error });
                    setUserData({ loggedIn: false, username: '', count: null });
            })
            .finally(() =>         setIsLoadingUserData(false));
    }, []);
    async function logInCallback(username: string, password: string) {
        if (!username || !password) {
            return;
        }
        const loginData = await logIn(username, password);
        setUserData({
            loggedIn: loginData.loggedIn,
            username: loginData.username,
            count: loginData.count,
        });
    }

    async function registerCallback(username: string, password: string) {
        if (!username || !password) {
            return;
        }
        const registerData = await register(username, password);
        setUserData({
            loggedIn: registerData.loggedIn,
            username: registerData.username,
            count: registerData.count,
        });
    }

    async function incrementCount() {
        setIsProcessingCount(true);
        try {
            const result = await fetch(`${BACKEND_URL}/api/increment`, {
                method: 'PATCH',
                credentials: 'include',
                headers: {
                    'Content-type': "application/json",
                }
            });
            const data = await result.json();
            setUserData({
                username: userData.username,
                loggedIn: userData.loggedIn,
                count: data.count,
            });
        } catch (error) {
            console.log('incrementCount error', error);
        } finally {
            setIsProcessingCount(false);
        }
    }

    async function signOut() {
        try {
            const result = await fetch(`${BACKEND_URL}/api/signout`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-type': "application/json",
                }
            });
            setUserData({
                username: '',
                loggedIn: false,
                count: null,
            });
        } catch (error) {
            console.log('signOut error', error);
        }
    }
  return (
    <>
        <main>
            {isLoadingUserData ? 'loading...' : userData.loggedIn ? <div>
                <span>
                    username: {userData.username}
                    <br />
                    count: {userData.count}
                    <br />
                    <button disabled={isProcessingCount} onClick={() => incrementCount()}>
                        Inc count
                    </button>
                    <br />
                    <button onClick={() => signOut()}>
                        Sign Out
                    </button>
                </span>
            </div> : <Auth logIn={logInCallback} register={registerCallback}/>}
            {/*<Users />*/}
            {/*<Register />*/}
        </ main>
    </>
  )
}

async function register(username: string, password: string) {
    try {
        const response = await fetch(`${BACKEND_URL}/api/register`, {
            method: 'POST',
            body: JSON.stringify({
                username,
                password,
            }),
            credentials: 'include',
            headers: {
                'Content-type': "application/json",
            }
        });

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error during registration', error);
        return {
            loggedIn: false,
            username: '',
            count: null,
        }
    }
}

async function logIn(username: string, password: string) {
    try {
        const response = await fetch(`${BACKEND_URL}/api/login`, {
            method: 'POST',
            body: JSON.stringify({
                username,
                password,
            }),
            credentials: 'include',
            headers: {
                'Content-type': "application/json",
            }
        });

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error during registration', error);
        return {
            loggedIn: false,
            username: '',
            count: null,
        }
    }
}

export default App
