<script lang="ts">
    import type { PageServerData } from "./$types";

    export let data: PageServerData;
</script>
<main class="container">
    <article>
        <p>Hi
            {#if data.user}
                {data?.user.name}
            {:else}
                ???
            {/if}
            <span style="font-size: 24px">&#128075;</span>
        </p>
        {#if data.error}
            <p style="color: red;">
                {data.error}
            </p>
        {/if}
    </article>
</main>