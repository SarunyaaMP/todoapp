import type { Actions, PageServerLoad } from "./$types";
import prisma from "$lib/server/prisma";
import { error, fail } from "@sveltejs/kit";

export const load : PageServerLoad = async ( { params: {todoid}}) => {

    const todo = await prisma.todo.findUnique({
        where:{
            id : Number(todoid),
        }
    })

    return { todo };
}

export const actions: Actions = {
    
    updateTodo: async( {request , params}) => {
        const data = await request.formData();
        const {text} = Object.fromEntries(data) as {
            text : string
        }

        try{
            await prisma.todo.update({
                where: {
                    id : Number(params.todoid),
                },
                data: {
                    text,
                }
            })
        }

        catch(error) {
            console.error(error);
            return fail(500, {message : 'Could not update todo'})
        }

        return {
            status:200
        }
    }
};