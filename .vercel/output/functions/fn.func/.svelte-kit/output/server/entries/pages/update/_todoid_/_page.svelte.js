import { c as create_ssr_component, b as add_attribute } from "../../../../chunks/ssr.js";
const Page = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let todo;
  let { data } = $$props;
  if ($$props.data === void 0 && $$bindings.data && data !== void 0)
    $$bindings.data(data);
  ({ todo } = data);
  return `<form class="my-6" action="?/updateTodo" method="post"><div class="flex flex-col text-sm mb-2"><label for="todo" class="font-bold mb-2 text-gray-800" data-svelte-h="svelte-1vd8zs6">Todo</label> <input type="text"${add_attribute("value", todo?.text, 0)} name="text" id="text" placeholder="What you gonna do?" class="appearance-none shadow-sm border border-gray-200 p-2 focus:outline-none focus:border-gray-500 rounded-lg" autocomplete="off"></div> <button type="submit" class="w-full shadow-sm rounded bg-blue-500 hover:bg-blue-600 text-white py-2 px-4" data-svelte-h="svelte-1anhru4">Done</button></form>`;
});
export {
  Page as default
};
