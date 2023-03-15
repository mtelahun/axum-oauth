import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad =  async (event) => {
    const { locals } = event;
    const user = locals.user;

    if (user) {
        return { user };
    }

    throw redirect(302, '/');
}
