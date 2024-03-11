import { writable, type Writable } from "svelte/store";

interface Todo {
    text: string;
    completed: boolean;
    id: number;
  }

export const todos : Writable<Todo[]>= writable([]);

export const addTodo = (text : string) => {
    todos.update((cur : Todo[] ) => {
        const newTodos = [...cur, {text, completed: false, id:Date.now()}];
        return newTodos;
    })
}

export const deleteTodo = (id : number) => {
    todos.update( todos => todos.filter(todo=> todo.id != id))
}

export const toggleTodoCompleted = (id : number) => {
    todos.update((todos:Todo[]) => {
        let index = -1;
        index = todos.findIndex(todo => todo.id === id);
        if(index != -1){
            todos[index].completed = !todos[index].completed;
        }
        return todos;
    })
}