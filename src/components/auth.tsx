import {useState} from "react";
import {BACKEND_URL} from "../constants.ts";

type callbackType = (username: string, password: string, withJwt: boolean) => void;

interface AuthProps {
    logIn: callbackType;
    register: callbackType;
}

function Auth({ logIn, register }: AuthProps) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [withJwt, setWithJwt] = useState(false);

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
            <button onClick={() => register(username, password, withJwt)}>
                Sign Up
            </button>
            <button onClick={() => logIn(username, password, withJwt)}>
                Log In
            </button>
            <br />
            <span>With JWT?</span>
            <input type="checkbox" checked={withJwt} onChange={() => setWithJwt(!withJwt)}/>
            <a href={`${BACKEND_URL}/api/login/discord`}>
                <button>
                    Discord login
                </button>
            </a>
            <br />
        </>

    )
}
export default Auth;
