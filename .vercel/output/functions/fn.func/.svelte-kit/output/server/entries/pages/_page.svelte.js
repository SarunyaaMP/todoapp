import { c as create_ssr_component, b as add_attribute, a as subscribe, e as escape, v as validate_component, d as each } from "../../chunks/ssr.js";
import "devalue";
import { p as page } from "../../chunks/stores.js";
import { w as writable } from "../../chunks/index2.js";
const TodoForm = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let { baseImage = writable("") } = $$props;
  let base64;
  if ($$props.baseImage === void 0 && $$bindings.baseImage && baseImage !== void 0)
    $$bindings.baseImage(baseImage);
  return `  <form class="my-6" action="?/createTodo" method="post" enctype="multipart/form-data"><div class="flex flex-col text-sm mb-2 space-y-2"><label for="todo" class="font-bold mb-2 text-gray-800" data-svelte-h="svelte-1vd8zs6">Todo</label> <input type="text" name="text" id="text" placeholder="What you gonna do?" class="appearance-none shadow-sm border border-gray-200 p-2 focus:outline-none focus:border-gray-500 rounded-lg" autocomplete="off"> <input type="hidden" name="image"${add_attribute("value", base64, 0)}> <input type="file" accept="image/*" class="w-full shadow-sm rounded bg-gray-500 hover:bg-gray-600 text-white py-2 px-4" id="image"></div> <button type="submit" class="w-full shadow-sm rounded bg-blue-500 hover:bg-blue-600 text-white py-2 px-4" data-svelte-h="svelte-17lmbkk">Submit</button></form>`;
});
const Page = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let todos;
  let $page, $$unsubscribe_page;
  $$unsubscribe_page = subscribe(page, (value) => $page = value);
  let { data } = $$props;
  if ($$props.data === void 0 && $$bindings.data && data !== void 0)
    $$bindings.data(data);
  ({ todos } = data);
  $$unsubscribe_page();
  return `<main><div>${$page.data.session ? `<p>Signed in as ${escape($page.data.session.user?.name)}</p> <h1 class="text-2xl font-bold text-center text-gray-800 md:text-3xl" data-svelte-h="svelte-9u0k6o">My todos</h1> ${validate_component(TodoForm, "TodoForm").$$render($$result, {}, {}, {})} ${each(todos, (todo) => {
    return `<li class="bg-white flex space-x-3 items-center shadow-sm border border-gray-200 rounded-lg my-2 py-2 px-4 "><img${add_attribute("src", todo.image, 0)} alt="base64_image" class="size-10"> <span${add_attribute("class", "flex-1 text-gray-800", 0)}>${escape(todo.text)}</span> <a href="${"/update/" + escape(todo.id, true)}" role="button" class="text-sm bg-gray-500 hover:bg-gray-600 text-white py-1 px-2 rounded focus:outline-none focus:shadow-outline">Edit</a> <form action="${"?/deleteTodo&id=" + escape(todo.id, true)}" method="post"><button type="submit" class="text-sm bg-red-500 hover:bg-red-600 text-white py-1 px-2 rounded focus:outline-none focus:shadow-outline" data-svelte-h="svelte-5bceyc">Delete
                        </button></form> </li>`;
  })} <button class="bg-gray-700 py-1 px-2 rounded text-white" data-svelte-h="svelte-e2fbar">Sign Out</button>` : `<h1 class="text-2xl font-bold text-center text-gray-800 md:text-3xl" data-svelte-h="svelte-li3w2t">Sign In</h1> <button class="bg-gray-700 py-1 px-2 rounded text-white" data-svelte-h="svelte-1gdgxqv">Sign In with GitHub</button>`}</div></main>`;
});
export {
  Page as default
};
