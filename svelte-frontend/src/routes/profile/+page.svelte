<script lang="ts">
    import type { PageServerData } from "./$types";

    export let data: PageServerData;
</script>
<main class="container">
    <h3>Profile</h3>
    <article>
        <p>Hi 
            {data.user.name} 
            <span style="font-size: 24px">&#128075;</span>
        </p>
        <p>Your Id is: {data.user.id}</p>
        <div><b>Authorized Clients</b></div>
        <ul>
            {#each data.user.authorized_clients as c}
                <li>
                    {c.name}
                </li>
            {/each}
        </ul>
    </article>
</main>