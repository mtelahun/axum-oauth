import { getUserInfo } from "./user";
import type { UserInfo } from "./user";

type SessionInfo = {
    access_token: string;
    user_info: UserInfo;
    invalidAt: number;

};

type Sid = string;

const sessionStore = new Map<Sid, SessionInfo>();

function getSid(): Sid {
    return crypto.randomUUID();
}

export async function createSession(access_token: string, maxAge: number): Promise<string> {
    let sid: Sid = '';

    do {
        sid = getSid();
    } while (sessionStore.has(sid));

    updateSession(sid, access_token, maxAge);

    return sid;
}

export function getSession(sid: Sid): SessionInfo | undefined {
    const session = sessionStore.get(sid);
    if (session) {
        if (Date.now() > session.invalidAt) {
            console.log('delete invalid session', sid);
            sessionStore.delete(sid);
            return undefined;
        } else {
            return session;
        }
    } else {
        console.log('session not found', sid)
        return undefined;
    }
}

export function deleteSession(sid: Sid) {
    if (sessionStore.has(sid)) {
        sessionStore.delete(sid);
    }
}

export async function updateSession(sid: Sid, access_token: string, maxAge: number) {
    console.debug('enter updateSession()');
    const uinfo: UserInfo = await getUserInfo(access_token);

    sessionStore.set(sid, {
        access_token,
        user_info: uinfo,
        invalidAt: Date.now() + maxAge,
    });
}
