 <!-- <script lang="ts">
    import { enhance } from "$app/forms";

 </script>
 
 <form class="my-6" action="?/createTodo" method="post" enctype="multipart/form-data" use:enhance>
    <div class="flex flex-col text-sm mb-2 space-y-2">
        <label for="todo" class="font-bold mb-2 text-gray-800">Todo</label>
        <input type="text" name="text" id="text" placeholder="What you gonna do?" class="appearance-none shadow-sm border border-gray-200 p-2 focus:outline-none focus:border-gray-500 rounded-lg" autocomplete="off"/>

        <input type="file" accept="image/*" class="w-full shadow-sm rounded bg-gray-500 hover:bg-gray-600 text-white py-2 px-4" name="image" id="image"/>
    </div>
    <button type="submit" class="w-full shadow-sm rounded bg-blue-500 hover:bg-blue-600 text-white py-2 px-4">Submit</button>
</form> -->

<script lang="ts">
    import { enhance } from "$app/forms";
    import { writable, type Writable } from 'svelte/store';
  
    export let baseImage: Writable<string> = writable('');

    let base64 : string;
  
    const convertImageToBase64 = async (e: Event) => {
      const target = e.target as HTMLInputElement;
      const file = target.files?.[0];
      if (!file) {
        return "error in convert image to base64";
      };
  
      base64 = await convertBase64(file);
      baseImage.set(base64);
    };
  
    const convertBase64 = (file: File): Promise<string> => {
      return new Promise((resolve, reject) => {
        const fileReader = new FileReader();
        fileReader.readAsDataURL(file);
  
        fileReader.onload = () => {
          if (fileReader.result && typeof fileReader.result === 'string') {
            resolve(fileReader.result);
          } else {
            reject(new Error('Failed to read file as Data URL.'));
          }
        };
  
        fileReader.onerror = (error) => {
          reject(error);
        };
      });
    };
  </script>
  
  <form class="my-6" action="?/createTodo" method="post" enctype="multipart/form-data" use:enhance>
      <div class="flex flex-col text-sm mb-2 space-y-2">
          <label for="todo" class="font-bold mb-2 text-gray-800">Todo</label>
          <input type="text" name="text" id="text" placeholder="What you gonna do?" class="appearance-none shadow-sm border border-gray-200 p-2 focus:outline-none focus:border-gray-500 rounded-lg" autocomplete="off"/>
  
          <input type="hidden" name="image" value={base64}/>
          <input type="file" accept="image/*" class="w-full shadow-sm rounded bg-gray-500 hover:bg-gray-600 text-white py-2 px-4" id="image" on:change={convertImageToBase64} />

      </div>
      <button type="submit" class="w-full shadow-sm rounded bg-blue-500 hover:bg-blue-600 text-white py-2 px-4">Submit</button>
  </form>
  