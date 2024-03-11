import type { Actions, PageServerLoad} from "./$types";
import  prisma  from "$lib/server/prisma"
import { fail } from "@sveltejs/kit";

export const load: PageServerLoad = async() => {
    return{
        todos: await prisma.todo.findMany()
    }
}

export const actions : Actions = {
    createTodo : async ( { request }) => {
        const data = await request.formData();
        const {text} = Object.fromEntries(data) as {
            text : string
        }

        try{
            await prisma.todo.create({
                data : {
                    text
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

    toggleTodo: async( { url }) => {
        console.log("toggling data");
        const id = url.searchParams.get("id");

        if(!id){
            return fail(400, { message: "Invalid request"})
        }

        try{
            const data = await prisma.todo.findUnique({
                where: {
                    id: Number(id)
                }
            });
            

            if( data?.completed != null){
                await prisma.todo.update({
                    where : {
                        id: Number(id)
                    },
                    data : {
                        completed : {
                            set : !data.completed
                        }
                    }
                })
            }
        }

        catch(error){
            console.error(error);
            return fail(500, {message : 'Something went wrong in toggle '})
        }

        return{
            status: 200
        }
    }
}
