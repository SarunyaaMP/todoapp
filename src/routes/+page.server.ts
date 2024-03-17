import type { Actions, PageServerLoad , PageData} from "./$types";
import  prisma  from "$lib/server/prisma"
import { fail, redirect } from "@sveltejs/kit";

export const config = {
    runtime: 'edge',
};

export const prerender = true;
export const load: PageServerLoad = async( {locals} ) => {

    const session = await locals.auth();
    // console.log('session', session);

    return{
        todos: await prisma.todo.findMany({
            include : {
                user : true
            }
        }),
        session: session
    }
}
 
export const actions : Actions = {
    createTodo : async ( { request , locals}) => {

        const session = await locals.auth();

        if(!session) {
            console.log('No session found!');
        }

        const data = await request.formData();

        // console.log(data);

        const {text , image} = Object.fromEntries(data) as {
            text : string,
            image : string
        }

        try{

            const prismaUser = await prisma.user.findUnique({
                where: {
                    email : session?.user?.email as string
                }
            })

            await prisma.todo.create({
                data : {
                    text,
                    image,
                    userId: prismaUser?.id
                }
            })
        }

        catch(error){
            console.error(error);
            return fail(500, {message : 'Could not create todo'})
        }

        return {
            status:201
        }
    },

    deleteTodo: async( { url }) => {
        const id = url.searchParams.get("id");

        if(!id){
            return fail(400, { message: "Invalid request"})
        }

        try{
            await prisma.todo.delete({
                where: {
                    id: Number(id)
                }
            })
        }

        catch(error){
            console.error(error);
            return fail(500, {message : 'Something went wrong in delete'})
        }

        return{
            status: 200
        }
    },
}

