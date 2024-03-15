export const manifest = (() => {
function __memo(fn) {
	let value;
	return () => value ??= (value = fn());
}

return {
	appDir: "_app",
	appPath: "_app",
	assets: new Set([]),
	mimeTypes: {},
	_: {
		client: {"start":"_app/immutable/entry/start.CBr9-MQ8.js","app":"_app/immutable/entry/app.D0cPIPhd.js","imports":["_app/immutable/entry/start.CBr9-MQ8.js","_app/immutable/chunks/entry.CPY-eWrb.js","_app/immutable/chunks/scheduler.Rzn6huuy.js","_app/immutable/entry/app.D0cPIPhd.js","_app/immutable/chunks/scheduler.Rzn6huuy.js","_app/immutable/chunks/index.D6xxGKKq.js"],"stylesheets":[],"fonts":[],"uses_env_dynamic_public":false},
		nodes: [
			__memo(() => import('../output/server/nodes/0.js')),
			__memo(() => import('../output/server/nodes/1.js')),
			__memo(() => import('../output/server/nodes/2.js')),
			__memo(() => import('../output/server/nodes/3.js'))
		],
		routes: [
			{
				id: "/",
				pattern: /^\/$/,
				params: [],
				page: { layouts: [0,], errors: [1,], leaf: 2 },
				endpoint: null
			},
			{
				id: "/update/[todoid]",
				pattern: /^\/update\/([^/]+?)\/?$/,
				params: [{"name":"todoid","optional":false,"rest":false,"chained":false}],
				page: { layouts: [0,], errors: [1,], leaf: 3 },
				endpoint: null
			}
		],
		matchers: async () => {
			
			return {  };
		},
		server_assets: {}
	}
}
})();
