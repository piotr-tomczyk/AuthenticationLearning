import { useState, useEffect } from 'react';
import { BACKEND_URL } from '../constants.ts';

function Users() {
    const [users, setUsers] = useState([]);
    useEffect(() => {
        fetch(`${BACKEND_URL}/api`)
            .then(response => response.json())
            .then(data => {
                setUsers(data.data);
            })
            .catch(error => console.error(error));
    }, []);

    return (
        <>
            {users.length ? users.map((user: User) => (
                <div key={user.userid}>
                    Name is {user.username}.
                </div>
            )) : <div> No users </div>}
        </>
    )
}

interface User {
    userid: string,
    username: string,
}
export default Users;
