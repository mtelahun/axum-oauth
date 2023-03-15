import { getSession, updateSession } from '$lib/session';
import { updateName } from '$lib/user';
import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad =  async (event) => {
    const { cookies, locals } = event;
    const sid = cookies.get('session');
    const maxAge = 60 * 60 * 24 * 30;
    let error = '';
    if (sid) {
        const session = getSession(sid);
        if (session) {
            const res = await updateName(session.access_token, 'Alice');
            if (res) {
                updateSession(sid, session.access_token, maxAge);
            } else {
                error = 'Unable to set user\'s Name. Check the console for errors.';
            }
        }
    } else {
        throw redirect(302, '/');
    }
    const user = locals.user;
    if (user) {
        return { user, error };
    }

    throw redirect(302, '/');
}
