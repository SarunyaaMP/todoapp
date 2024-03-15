// used to pass the current session into page.data.session
// load -> load serverside any data we need
import type { LayoutServerLoad } from "./$types";

export const load : LayoutServerLoad = async (event) => {
    return {
        session : await event.locals.auth()
    }
}
 