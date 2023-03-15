// See https://kit.svelte.dev/docs/types#app
// for information about these interfaces
declare global {
	namespace App {
		// interface Error {}

		interface Locals {
			user: UserInfo;
		}
		
		// interface PageData {}
		// interface Platform {}
        
		interface ClientForm {
            name: string,
            redirect_uri: string,
            type: string,
        }
	}
}

export {};
