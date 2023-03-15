import type { Actions, PageServerLoad } from './$types';
import { error, redirect } from '@sveltejs/kit';
import { createHash, randomBytes, type BinaryLike } from 'crypto';
import { client_id, client_secret, code_verifier, code_challenge } from './authorize/store.js';

interface ClientForm {
    name: string,
    redirect_uri: string,
    type: string,
}

type ClientCredential = {
    client_id: string,
    client_secret: string,
}

export const load: PageServerLoad =  async (event) => {
    const { locals } = event;
    const user = locals.user;

    if (user) {
        return { user };
    }

}


export const actions = {
	default: async ({ request }) => {

        const data =  await request.formData();
        const do_register = data.get('register_client');
        if (do_register) {
            const client_cred = await register_client();
            if (client_cred) {
                client_id.update(() => client_cred.client_id);
                client_secret.update(() => client_cred.client_secret);
            } else {
                throw error(500, 'unable to register client');
            }
        }
        
        let c_id = '';
        client_id.subscribe(value => {
            c_id = value;
        });
        const verifier = base64URLEncode(randomBytes(32));
        const challenge = base64URLEncode(sha256(verifier));
        code_verifier.update(() => verifier);
        code_challenge.update(() => challenge);
        const authorization_url = 'http://localhost:3000/oauth/authorize?' +
            new URLSearchParams({
                'response_type': 'code',
                'redirect_uri': 'http://localhost:5173/authorize',
                'client_id': c_id,
                'scope': 'account:read',
                'code_challenge': challenge,
                'code_challenge_method': 'S256',
                'state': '12345',
        }).toString();

        throw redirect(302, authorization_url);
	}
} satisfies Actions;

// Dependency: Node.js crypto module
// https://nodejs.org/api/crypto.html#crypto_crypto
function base64URLEncode(str: Buffer) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Dependency: Node.js crypto module
// https://nodejs.org/api/crypto.html#crypto_crypto
function sha256(buffer: BinaryLike) {
    return createHash('sha256').update(buffer).digest();
}

async function register_client() {
    const form = {
        'name': 'axum-oauth-frontend',
        'redirect_uri': 'http://localhost:5173/authorize',
        'type': 'confidential',
    };
    const form_body = Object.keys(form).map(key =>
        encodeURIComponent(key) + '=' + encodeURIComponent(form[key as keyof ClientForm])).join('&');

    console.log("form_body: " + form_body);
    console.log("Fetching...");
    const response = await fetch(
        'http://localhost:3000/oauth/client',
        {
            method: 'POST',
            headers: {
                'Content-Type': "application/x-www-form-urlencoded",
            },
            body: form_body,
        }
    );

    if (!response.ok) {
        const error = (await response.text());
        console.log("error: unable to register client: " + error);
        return;
    }

    const client_cred: ClientCredential = JSON.parse(await response.text());
    console.log(client_cred);
    
    return client_cred;
}
