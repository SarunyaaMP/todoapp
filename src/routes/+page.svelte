<script lang="ts">
    import TodoForm from "../components/TodoForm.svelte";
    import Todo from "../components/Todo.svelte";
    import type { PageData } from "./$types";
    import { signIn , signOut } from "@auth/sveltekit/client";
    // signIn() -> runs logic to sign in user, signIn("github") -> use the sign in with github logic
    // signOut() -> runs logic to sign out user
    import { page } from "$app/stores";
    import { enhance } from "$app/forms";
    // console.log($page.data.session?.user?.email);
    // $page.data.session -> {user, image, etc..} AUTH session
    //console.log($page.data.session);

    export let data: PageData;

    $: ( { todos } = data)

</script>

<main>

    <div>    

        {#if $page.data.session}

            <p>
                Signed in as {$page.data.session.user?.name}
            </p>

            <h1 class="text-2xl font-bold text-center text-gray-800 md:text-3xl">
                My todos
            </h1>

            <TodoForm/>

            {#each todos as todo}

                 <li class="bg-white flex space-x-3 items-center shadow-sm border border-gray-200 rounded-lg my-2 py-2 px-4 ">
                    
                    <img src={todo.image} alt="base64_image" class="size-10" />
                    <span class={"flex-1 text-gray-800"}>{todo.text}</span>

                    <a href="/update/{todo.id}" role="button" class="text-sm bg-gray-500 hover:bg-gray-600 text-white py-1 px-2 rounded focus:outline-none focus:shadow-outline">Edit</a>

                    <form action="?/deleteTodo&id={todo.id}" method="post">
                        <button type="submit" class="text-sm bg-red-500 hover:bg-red-600 text-white py-1 px-2 rounded focus:outline-none focus:shadow-outline" >
                            Delete
                        </button>
                    </form>
                </li> 

            {/each}

            <button on:click={() => signOut()} class="bg-gray-700 py-1 px-2 rounded text-white">Sign Out</button>

        {:else}
            
            <h1 class="text-2xl font-bold text-center text-gray-800 md:text-3xl">Sign In</h1>
            <button on:click={() => signIn("github")} class="bg-gray-700 py-1 px-2 rounded text-white"> Sign In with GitHub </button>
 
        {/if}
    </div>
</main>