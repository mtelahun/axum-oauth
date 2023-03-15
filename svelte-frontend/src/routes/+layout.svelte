<script lang="ts">
    import type { LayoutServerData } from "./$types";

    export let data: LayoutServerData;
</script>
<nav>
    <ul>
        <li><strong>Axum OAuth Demo Frontend</strong></li>
    </ul>
    <ul>
        <li><a href="/">Home</a></li>
        <li><a href="/protected">Protected Resource</a></li>
        {#if data?.user}
            <li><a href="/profile">My Profile</a></li>
        {/if}
        {#if data?.user}
            <form method="POST" action="/logout">
                <button type="submit">Log out</button>
            </form>
        {:else}
            <li><a href="/register" role="button">Sign up</a></li>
        {/if}
    </ul>
</nav>

<slot />
