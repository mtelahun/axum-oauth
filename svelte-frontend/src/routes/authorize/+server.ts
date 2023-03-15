import { error, redirect } from '@sveltejs/kit';

import type { RequestHandler } from './$types';

import { client_id, client_secret, code_verifier } from './store.js';
import { createSession } from '$lib/session';

const tokenURL = 'http://localhost:3000/oauth/token'

interface TokenRequest {
    grant_type: string,
    redirect_uri: string,
    code_verifier: string,
    code: string,
}

export const GET = ( async ({ cookies, url }) => {
    const code = url.searchParams.get('code') || '';
    const state = url.searchParams.get('state') || '';
    console.debug('Authorization code: ' + code);
    console.debug('State: ' + state);
    if (state != '12345') {
        throw error(500, "Authorization state does not match. Aborting.");
    }
    const token = await getAccessToken(code)
    console.debug('Access Token: ' + token);
    // access_token.update(() => token);

    const maxAge = 60 * 60 * 24 * 30;
    const session_id: string = await createSession(token, maxAge);
    
    cookies.set('session', session_id, {
        path: '/',
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production',
        maxAge: maxAge,
    });

    // const session_data: SessionData = {
    //     id: cookie_token,
    //     access_token: token,
    // };
    // const db = session_db;
    // db.set(session_data);

    throw redirect(302, '/profile');
}) satisfies RequestHandler;

function getAccessToken(code: string) {

    let c_id = '';
    let c_secret = '';
    let verifier = '';
    client_id.subscribe(value => {
        c_id = value;
    });
    client_secret.subscribe(value => {
        c_secret = value;
    })
    code_verifier.subscribe(value => {
        verifier = value;
    });
    const form = {
        grant_type: 'authorization_code',
        redirect_uri: 'http://localhost:5173/authorize',
        code_verifier: verifier,
        code,
    };
    const form_body = Object.keys(form).map(key =>
        encodeURIComponent(key) + '=' + encodeURIComponent(form[key as keyof TokenRequest])).join('&');
    return fetch(tokenURL, {
        method: 'POST',
        headers: {
            'Authorization': 'Basic ' + Buffer.from(c_id + ":" + c_secret).toString('base64'),
            'Content-Type': "application/x-www-form-urlencoded",
            Accept: 'application/json' 
        },
        body: form_body,
    }).then(r => r.json())
        .then(r => r.access_token)
}
