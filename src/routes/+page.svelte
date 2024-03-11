<script lang="ts">
    import TodoForm from "../components/TodoForm.svelte";
    // import Todo from "../components/Todo.svelte";
    // import {todos} from "../store/todoStore"

    import type { PageData } from "./$types";

    export let data: PageData

    $: ( { todos } = data)

    // const toggleData = async () => {
    //     try{

    //         const response = await fetch(`?/toggleTodo` , {
    //             method : 'POST'
    //         })

    //         console.log("Error after fetch");

    //         if (response.ok) {
    //             console.log('Data toggled successfully');
    //         } 
    //         else {
    //             console.error('Error toggling data');
    //         }
    //     }

    //     catch(error) {
    //         console.error("error in toggling");
    //     }
    // }
</script>

<main>
    <h1 class="text-2xl font-bold text-center text-gray-800 md:text-3xl">
        My todos
    </h1>

    <TodoForm/>

    {#each todos as todo}
    <!-- <Todo todo={todo}/> -->
    <li class="bg-white flex space-x-3 items-center shadow-sm border border-gray-200 rounded-lg my-2 py-2 px-4 ">
        <!-- <input 
            name = "completed"
            type="checkbox"
            id="completed"
            checked = {todo.completed}
            class="mr-2 form-checkbox h-5 w-5"  
        /> -->

        <!--on:change={toggleData}-->
    
        <span class={`flex-1 text-gray-800 ${todo.completed ? 'line-through' : ''}`}>{todo.text}</span>
        <a href="/update/{todo.id}" role="button" class="text-sm bg-gray-500 hover:bg-gray-600 text-white py-1 px-2 rounded focus:outline-none focus:shadow-outline">Edit</a>

        <form action="?/deleteTodo&id={todo.id}" method="post">
            <button type="submit" class="text-sm bg-red-500 hover:bg-red-600 text-white py-1 px-2 rounded focus:outline-none focus:shadow-outline" >
                Delete
            </button>
        </form>
    </li>
    {/each}
</main>