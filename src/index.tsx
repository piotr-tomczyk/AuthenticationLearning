import { serve, sql, SQL } from "bun";
import index from "./index.html";
import bcrypt from 'bcrypt';
import crypto from "node:crypto";
import fs from "node:fs/promises";
import jwt from 'jsonwebtoken';

const pg = new SQL('postgres://postgres:admin@localhost:5432/auth');
const authUsersTableName = 'auth.public.users';
const authSessionsTableName = 'auth.public.sessions';

// @ts-ignore
// @ts-ignore
const server = serve({
    routes: {
        // Serve index.html for all unmatched routes.
        "/*": index,

        "/api/me": {
            async GET(req) {
                const cookies = req.cookies;
                const sessionId = cookies.get('sessionId');
                const authJwtToken = cookies.get('authJwtToken');
                const refreshJwtToken = cookies.get('refreshJwtToken');
                if (!checkIfCookieExist(sessionId) &&
                    !checkIfCookieExist(authJwtToken) &&
                    !checkIfCookieExist(refreshJwtToken)
                ) {
                    return Response.json({
                        loggedIn: false,
                    });
                }

                let userId: string | null = null;
                let user: User | null = null;
                if (checkIfCookieExist(sessionId)) {
                    const responseSession = await pg`SELECT *
                                                     FROM ${sql(authSessionsTableName)}
                                                     WHERE sessionid = ${sessionId}`;
                    const session = responseSession?.[0];
                    if (!responseSession.length) {
                        return Response.json({
                            loggedIn: false,
                        });
                    }

                    userId = session?.userid;
                    if (session.expiresat?.getTime() < Date.now()) {
                        return Response.json({
                            loggedIn: false,
                        })
                    }
                } else if (checkIfCookieExist(refreshJwtToken)) {
                    const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8' });
                    try {
                        const payload = jwt.verify(refreshJwtToken as string, secret);
                        if (typeof payload === "string") {
                            throw new Error("Invalid JWT payload: expected object, got string");
                        }
                        if (!payload.userId) {
                            throw new Error("UserID expected to exist");
                        }
                        userId = payload.userId;
                        const responseUser = await pg`SELECT * FROM ${sql(authUsersTableName)} WHERE userid = ${userId}`;
                        user = responseUser?.[0];
                        if (user?.refresh_jwt_version !== payload?.version) {
                            console.error('Refresh JWT version doesnt match');
                            return Response.json({}, { status: 401 });
                        } else {
                            const authJwtToken = await createJwt(userId as string);
                            req.cookies.set('authJwtToken', authJwtToken, {
                                expires: new Date(Date.now() + 1000 * 60 * 2),
                                secure: false,
                                httpOnly: true,
                                sameSite: 'strict',
                            });
                        }
                    } catch (error) {
                        console.error('api/me Error verifying refreshJWT', error);
                        return Response.json({}, {status: 401 });
                    }
                } else {
                    return Response.json({
                        loggedIn: false,
                    })
                }

                if (!user) {
                    const responseUser = await pg`SELECT * FROM ${sql(authUsersTableName)} WHERE userid = ${userId}`;
                    user = responseUser[0];
                }

                return Response.json({
                    loggedIn: true,
                    username: user?.username,
                    count: user?.count,
                });
            },
            async PUT(req) {
                return Response.json({
                    message: "Hello, world!",
                    method: "PUT",
                });
            },
        },
        "/api/login": {
            async POST(req) {
                const body = await req.json();
                const { username, password, withJwt } = body;

                try {
                    const response = await pg`SELECT *
                                              FROM ${sql(authUsersTableName)}
                                              WHERE username = ${username}
                                                AND login_type != 'discord'`;
                    if (!response?.length) {
                        return Response.json({loggedIn: false}, {status: 400});
                    }
                    const user = response[0];
                    const isPasswordValid = await validPassword(password, user.password);
                    if (!isPasswordValid) {
                        return Response.json({loggedIn: false}, {status: 401});
                    }
                    if (withJwt) {
                        const userId = user.userid;
                        const refreshTokenVersion = user.refresh_jwt_version;
                        const authJwtToken = await createJwt(userId);
                        const refreshJwtToken = await createRefreshJwt(userId, refreshTokenVersion);
                        req.cookies.set('authJwtToken', authJwtToken, {
                            expires: new Date(Date.now() + 1000 * 60 * 2),
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });

                        req.cookies.set('refreshJwtToken', refreshJwtToken, {
                            expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });

                        req.cookies.set('sessionId', 'j:null', {
                            expires: 1,
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });
                    } else {
                        const session = await createSession(user.userid);
                        req.cookies.set('sessionId', session, {
                            expires: new Date(Date.now() + 1000 * 3600 * 24 * 30),
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });
                    }
                    // Response.setHeader('Content-Type', 'application/json');
                    return Response.json({loggedIn: true, username: user.username, count: user.count});
                } catch (error) {
                    console.error('api/login Login error', error);
                    return Response.json({loggedIn: false}, {status: 500});
                }
            }
        },
        "/api/register": {
            async POST(req) {
                const body = await req.json();
                const { username, password, withJwt, } = body;
                try {
                    const response = await pg`SELECT username FROM ${sql(authUsersTableName)} WHERE username = ${username}`;
                    if (response?.length > 0) {
                        return Response.json({ loggedIn: false }, { status: 400 });
                    }
                    const hashedPassword = await generatePassword(password);
                    const userId = crypto.randomUUID();
                    await pg`INSERT INTO ${sql(authUsersTableName)} (userid, username, password) VALUES (${userId}, ${username}, ${hashedPassword})`;
                    if (withJwt) {
                        const authJwtToken = await createJwt(userId);
                        const refreshJwtToken = await createRefreshJwt(userId, "1");
                        req.cookies.set('authJwtToken', authJwtToken, {
                            expires: new Date(Date.now() + 1000 * 60 * 2),
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });

                        req.cookies.set('refreshJwtToken', refreshJwtToken, {
                            expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });
                    } else {
                        const session = await createSession(userId);
                        req.cookies.set('sessionId', session, {
                            expires: new Date(Date.now() + 1000 * 3600 * 24 * 30),
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });
                    }

                    return Response.json({ loggedIn: true, username, count: 0 }, { status: 201 });
                } catch(error) {
                    console.error('api/register Registration error', error);
                    return Response.json({ loggedIn: false }, { status: 500 });
                }
            }
        },
        "/api/signout": {
            async POST(req) {
                try {
                    const sessionId = req.cookies.get('sessionId');
                    const authJwtToken = req.cookies.get('authJwtToken');
                    const refreshJwtToken = req.cookies.get('refreshJwtToken');

                    if (checkIfCookieExist(sessionId)
                        && checkIfCookieExist(authJwtToken)
                        && checkIfCookieExist(refreshJwtToken)) {
                        req.cookies.set('sessionId', "j:null", {
                            expires: 1,
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });
                        req.cookies.set('authJwtToken', "j:null", {
                            expires: 1,
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });
                        req.cookies.set('refreshJwtToken', "j:null", {
                            expires: 1,
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });

                        return Response.json({}, { status: 401 });
                    }

                    if (checkIfCookieExist(refreshJwtToken)) {
                        const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8' });
                        try {
                            const payload = jwt.verify(refreshJwtToken as string, secret);
                            if (typeof payload === "string") {
                                throw new Error("Invalid JWT payload: expected object, got string");
                            }
                            if (!payload.userId) {
                                throw new Error("UserID expected to exist");
                            }

                            const { userId } = payload;
                            const newVersion = crypto.randomUUID();
                            await pg`UPDATE ${sql(authUsersTableName)} SET refresh_jwt_version = ${newVersion} WHERE userid = ${userId}`;
                        } catch (error) {
                            console.error('api/signout Error verifying refreshJWT or updating refresh_token_version', error);
                            return Response.json({}, { status: 401 });
                        }

                        req.cookies.set('refreshJwtToken', "j:null", {
                            expires: 0,
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });
                        req.cookies.set('authJwtToken', "j:null", {
                            expires: 0,
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });
                    }
                    if (checkIfCookieExist(sessionId)) {
                        const responseSession = await pg`SELECT * FROM ${sql(authSessionsTableName)} WHERE sessionid = ${sessionId}`;
                        if (!responseSession.length) {
                            req.cookies.set('sessionId', "j:null", {
                                expires: 0,
                                secure: false,
                                httpOnly: true,
                                sameSite: 'strict',
                            });
                            return Response.json({}, { status: 401 });
                        }
                        await pg`DELETE FROM ${sql(authSessionsTableName)} WHERE sessionid=${sessionId}`;
                        req.cookies.set('sessionId', "j:null", {
                            expires: 0,
                            secure: false,
                            httpOnly: true,
                            sameSite: 'strict',
                        });
                    }
                    return Response.json({}, { status: 200 });
                } catch(error) {
                    console.error('api/signout Error', error);
                    return Response.json({}, { status: 500 });
                }
            }
        },
        "/api/increment": {
            async PATCH(req) {
                const sessionId = req.cookies.get('sessionId');
                const authJwtToken = req.cookies.get('authJwtToken');
                const refreshJwtToken = req.cookies.get('refreshJwtToken');

                if (checkIfCookieExist(sessionId)
                    && checkIfCookieExist(authJwtToken)
                    && checkIfCookieExist(refreshJwtToken)) {
                    return Response.json({}, { status: 401 });
                }
                let userId;
                let user;
                if (checkIfCookieExist(authJwtToken)) {
                    const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8' });
                    try {
                        const payload = jwt.verify(authJwtToken as string, secret);
                        if (typeof payload === "string") {
                            throw new Error("Invalid JWT payload: expected object, got string");
                        }
                        if (!payload.userId) {
                            throw new Error("UserID expected to exist");
                        }

                        userId = payload.userId;
                    } catch (error: any) {
                        if (error.message !== 'jwt expired') {
                            console.error('api/increment Error verifying authJWT', error);
                            return Response.json({}, { status: 401 });
                        }
                        try {
                            const payload = jwt.verify(refreshJwtToken as string, secret);
                            if (typeof payload === "string") {
                                throw new Error("Invalid JWT payload: expected object, got string");
                            }
                            if (!payload.userId) {
                                throw new Error("UserID expected to exist");
                            }
                            userId = payload.userId;
                            const responseUser = await pg`SELECT * FROM ${sql(authUsersTableName)} WHERE userid = ${userId}`;
                            user = responseUser[0];
                            if (user.refresh_jwt_version !== payload.version) {
                                console.error('Refresh JWT version doesnt match');
                                return Response.json({}, { status: 401 });
                            } else {
                                const authJwtToken = await createJwt(userId);
                                req.cookies.set('authJwtToken', authJwtToken, {
                                    expires: new Date(Date.now() + 1000 * 60 * 2),
                                    secure: false,
                                    httpOnly: true,
                                    sameSite: 'strict',
                                });
                            }
                        } catch (error) {
                            console.error('api/increment Error verifying refreshJWT', error);
                            return Response.json({}, { status: 401 });
                        }
                    }
                } else {
                    const responseSession = await pg`SELECT * FROM ${sql(authSessionsTableName)} WHERE sessionid = ${sessionId}`;
                    if (!responseSession.length) {
                        return Response.json({}, { status: 401 });
                    }
                    const session = responseSession?.[0];
                    if (session?.expiresat.getTime() < Date.now()) {
                        return Response.json({}, { status: 401 });
                    }
                    userId = session.userid;
                }
                const countResponse = await pg`UPDATE ${sql(authUsersTableName)} SET count = count + 1 WHERE userid=${userId} RETURNING count`;
                return Response.json({ count: countResponse[0].count, }, { status: 200 });
            }
        },
    },

    development: process.env.NODE_ENV !== "production" && {
        // Enable browser hot reloading in development
        hmr: true,

        // Echo console logs from the browser to the server
        console: true,
    },
});

console.log(`🚀 Server running at ${server.url}`);

interface User {
    id: string;
    username: string;
    password: string;
    count: number;
    refresh_jwt_version: string;
}

function checkIfCookieExist(cookieValue: string | null) {
    return cookieValue && cookieValue !== 'j:null';
}

function validPassword(password: string, hash: string) {
    return bcrypt.compare(password, hash);
}

async function createSession(userId: string) {
    await pg`DELETE FROM ${sql(authSessionsTableName)} WHERE expiresat<to_timestamp(${Math.floor(Date.now() / 1000)})`;
    const sessionId = crypto.randomUUID();
    await pg`INSERT INTO ${sql(authSessionsTableName)} (sessionid, userid, expiresat) VALUES (${sessionId}, ${userId}, to_timestamp(${Math.floor((Date.now() + 1000 * 3600 * 24 * 30) / 1000)}))`;
    return sessionId;
}

async function createJwt(userId: string) {
    const payload = {
        userId,
    };
    const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8' });
    const jwtToken = jwt.sign(payload, secret, { algorithm: 'RS256', expiresIn: '1m' });
    return jwtToken;
}

async function createRefreshJwt(userId: string, version = "1") {
    const payload = {
        userId,
        version,
    };
    const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8' });
    const jwtToken = jwt.sign(payload, secret, { algorithm: 'RS256', expiresIn: '30d' });
    return jwtToken;
}

async function generatePassword(password: string) {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
}
