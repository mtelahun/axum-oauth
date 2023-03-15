import { writable } from 'svelte/store';

export const client_id = writable('');
export const client_secret = writable('');
export const code_verifier = writable('');
export const code_challenge = writable('');
export const access_token = writable('');
