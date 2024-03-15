import * as server from '../entries/pages/update/_todoid_/_page.server.ts.js';

export const index = 3;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/pages/update/_todoid_/_page.svelte.js')).default;
export { server };
export const server_id = "src/routes/update/[todoid]/+page.server.ts";
export const imports = ["_app/immutable/nodes/3.ZJYJJXTg.js","_app/immutable/chunks/scheduler.Rzn6huuy.js","_app/immutable/chunks/index.D6xxGKKq.js"];
export const stylesheets = [];
export const fonts = [];
