<script lang="ts">
    import type { PageData } from "./$types";

    export let data: PageData;

    $: ( { todo } = data);
</script>


<form class="my-6" action="?/updateTodo" method="post">
    <div class="flex flex-col text-sm mb-2">
        <label for="todo" class="font-bold mb-2 text-gray-800">Todo</label>
        <input type="text" value={todo?.text} name="text" id="text" placeholder="What you gonna do?" class="appearance-none shadow-sm border border-gray-200 p-2 focus:outline-none focus:border-gray-500 rounded-lg" autocomplete="off"/>
    </div>
    <button type="submit" class="w-full shadow-sm rounded bg-blue-500 hover:bg-blue-600 text-white py-2 px-4">Done</button>
</form>