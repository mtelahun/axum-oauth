import type { Actions } from "@sveltejs/kit";
import { deleteSession } from '$lib/session';
import { redirect } from '@sveltejs/kit';

export const actions = {
    default: async (event ) => {
        const { cookies, locals } = event;
        const sid = cookies.get('session');
        if (sid) {
            deleteSession(sid);
            cookies.delete('session');
            locals.user = undefined;
        } else {
            console.log("logout: no valid session cookie found");
        }

        throw redirect(302, '/');

    }
} satisfies Actions;
