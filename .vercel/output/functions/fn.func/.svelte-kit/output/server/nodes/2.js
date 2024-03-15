import * as server from '../entries/pages/_page.server.ts.js';

export const index = 2;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/pages/_page.svelte.js')).default;
export { server };
export const server_id = "src/routes/+page.server.ts";
export const imports = ["_app/immutable/nodes/2.DpHx5-6N.js","_app/immutable/chunks/scheduler.Rzn6huuy.js","_app/immutable/chunks/index.D6xxGKKq.js","_app/immutable/chunks/entry.CRciQdia.js","_app/immutable/chunks/stores.DB6exevr.js"];
export const stylesheets = [];
export const fonts = [];
