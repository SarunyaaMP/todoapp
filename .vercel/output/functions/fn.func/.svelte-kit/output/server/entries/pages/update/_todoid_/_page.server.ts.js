import { p as prisma } from "../../../../chunks/prisma.js";
import { f as fail } from "../../../../chunks/index.js";
const load = async ({ params: { todoid } }) => {
  const todo = await prisma.todo.findUnique({
    where: {
      id: Number(todoid)
    }
  });
  return { todo };
};
const actions = {
  updateTodo: async ({ request, params }) => {
    const data = await request.formData();
    const { text } = Object.fromEntries(data);
    try {
      await prisma.todo.update({
        where: {
          id: Number(params.todoid)
        },
        data: {
          text
        }
      });
    } catch (error2) {
      console.error(error2);
      return fail(500, { message: "Could not update todo" });
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
