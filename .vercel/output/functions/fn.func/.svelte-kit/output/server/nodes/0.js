import * as server from '../entries/pages/_layout.server.ts.js';

export const index = 0;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/pages/_layout.svelte.js')).default;
export { server };
export const server_id = "src/routes/+layout.server.ts";
export const imports = ["_app/immutable/nodes/0.BP2RGMm6.js","_app/immutable/chunks/scheduler.Rzn6huuy.js","_app/immutable/chunks/index.D6xxGKKq.js","_app/immutable/chunks/stores.CgIKrO6n.js","_app/immutable/chunks/entry.CPY-eWrb.js"];
export const stylesheets = ["_app/immutable/assets/0.CwaW_QGf.css"];
export const fonts = [];
