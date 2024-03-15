<script lang="ts">
    import "../app.css";
    import { page } from "$app/stores";
    // $page.data.session -> {user, image, etc..} AUTH session
</script>

  <div class="container mx-auto my-6 max-w-lg">
    {#if $page.data.session}
    <hgroup>
      <h2>
        <a href="/" class="text-sm text-center text-gray-800 md:text-lg"> Home Page</a>
      </h2>
    </hgroup>
    {/if}
    <slot/>
  </div>