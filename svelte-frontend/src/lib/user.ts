type ClientInfo = {
    id: string,
    name: string,
}

export type UserInfo = {
    id: string,
    login: string,
    name: string,
    authorized_clients: Array<ClientInfo>,
}

const userURL = 'http://localhost:3000/api/user'

export async function getUserInfo(token: string): Promise<UserInfo> {
    const user_info: UserInfo = await getUser(token);
    console.log(user_info);

    return user_info

}

function getUser(access_token: string): Promise<UserInfo> {

    return fetch(userURL, {
        headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${access_token}`
        }
    })
        .then(r => r.json())
        .catch(error => {console.debug(error); return {id: '', login: '', authorized_clients: []};});

}

export async function updateName(access_token: string, name: string): Promise<boolean> {

    const response = await fetch(userURL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            Authorization: `Bearer ${access_token}`
        },
        body: JSON.stringify({ 'given_name': name}),
    });
    console.debug("response status: ", response.status, response.statusText);
    if (!response.ok) {
        return false;
    }

    return true;
}
