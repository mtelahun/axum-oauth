import type { Handle } from "@sveltejs/kit";
import { getSession } from "./lib/session";

export const handle: Handle = (async ({ event, resolve }) => {

    const sid = event.cookies.get('session');
    if (sid) {
        const session = getSession(sid);
        if (session) {
            event.locals.user = session.user_info;
        } else {
            event.cookies.delete(sid);
        }
    }

    return await resolve(event);
}) satisfies Handle;
