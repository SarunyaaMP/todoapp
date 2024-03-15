import { c as create_ssr_component, a as subscribe } from "../../chunks/ssr.js";
import { p as page } from "../../chunks/stores.js";
const Layout = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let $page, $$unsubscribe_page;
  $$unsubscribe_page = subscribe(page, (value) => $page = value);
  $$unsubscribe_page();
  return `<div class="container mx-auto my-6 max-w-lg">${$page.data.session ? `<hgroup data-svelte-h="svelte-1mybkef"><h2><a href="/" class="text-sm text-center text-gray-800 md:text-lg">Home Page</a></h2></hgroup>` : ``} ${slots.default ? slots.default({}) : ``}</div>`;
});
export {
  Layout as default
};
