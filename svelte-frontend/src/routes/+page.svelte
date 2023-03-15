<script lang="ts">
    import type { PageServerData } from "./$types";

    export let data: PageServerData;
</script>
<main class="container">
    <article>
        <div>
            {#if data?.user}
                <div>You are currently signed in</div>
            {:else}
                <form method="POST">
                    <button type="submit">Sign In with OAuth</button>
                    <div>
                        <input type="checkbox" id="register_client" name="register_client" checked/>
                        <lable for="register_client">Register a new client</lable>
                    </div>
                </form>
            {/if}
        </div>
    </article>
</main>
