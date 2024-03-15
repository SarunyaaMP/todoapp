import { p as prisma } from "../../chunks/prisma.js";
import { f as fail } from "../../chunks/index.js";
const load = async ({ locals }) => {
  const session = await locals.auth();
  return {
    todos: await prisma.todo.findMany(),
    session
  };
};
const actions = {
  createTodo: async ({ request, locals }) => {
    const session = await locals.auth();
    if (!session) {
      console.log("No session found!");
    }
    const data = await request.formData();
    const { text, image } = Object.fromEntries(data);
    try {
      const prismaUser = await prisma.user.findUnique({
        where: {
          email: session?.user?.email
        }
      });
      await prisma.todo.create({
        data: {
          text,
          image,
          userId: prismaUser?.id
        }
      });
    } catch (error) {
      console.error(error);
      return fail(500, { message: "Could not create todo" });
    }
    return {
      status: 201
    };
  },
  deleteTodo: async ({ url }) => {
    const id = url.searchParams.get("id");
    if (!id) {
      return fail(400, { message: "Invalid request" });
    }
    try {
      await prisma.todo.delete({
        where: {
          id: Number(id)
        }
      });
    } catch (error) {
      console.error(error);
      return fail(500, { message: "Something went wrong in delete" });
    }
    return {
      status: 200
    };
  }
};
export {
  actions,
  load
};
