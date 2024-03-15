
import { SvelteKitAuth } from "@auth/sveltekit";
import Github from "@auth/sveltekit/providers/github";
import { GITHUB_ID, GITHUB_SECRET} from "$env/static/private";
import { PrismaAdapter } from "@auth/prisma-adapter";
import prisma from "./lib/server/prisma";

//If github talks back to our application, it is handled by the "handle" here
export const { handle , signIn , signOut} = SvelteKitAuth({
    adapter: PrismaAdapter(prisma),
    providers : [
        Github({ clientId: GITHUB_ID, clientSecret: GITHUB_SECRET})
    ]
})

console.log("On hooks.server.ts",handle.name);

