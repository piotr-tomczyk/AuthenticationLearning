import {useState} from "react";

type callbackType = (username: string, password: string) => void;

interface AuthProps {
    logIn: callbackType;
    register: callbackType;
}

function Auth({ logIn, register}: AuthProps) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    return (
        <>
            <div>Uname</div>
            <input type="text"
                        value={username}
                    onChange={e => setUsername(e.target.value)} />
            <div>Pass</div>
            <input type="text"
                   value={password}
                   onChange={e => setPassword(e.target.value)} />
            <br />
            <button onClick={() => register(username, password)}>
                Sign Up
            </button>
            <button onClick={() => logIn(username, password)}>
                Log In
            </button>
        </>

    )
}
export default Auth;
