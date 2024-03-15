<!-- # create-svelte

Everything you need to build a Svelte project, powered by [`create-svelte`](https://github.com/sveltejs/kit/tree/main/packages/create-svelte).

## Creating a project

If you're seeing this, you've probably already done this step. Congrats!

```bash
# create a new project in the current directory
npm create svelte@latest

# create a new project in my-app
npm create svelte@latest my-app
```

## Developing

Once you've created a project and installed dependencies with `npm install` (or `pnpm install` or `yarn`), start a development server:

```bash
npm run dev

# or start the server and open the app in a new browser tab
npm run dev -- --open
```

## Building

To create a production version of your app:

```bash
npm run build
```

You can preview the production build with `npm run preview`.

> To deploy your app, you may need to install an [adapter](https://kit.svelte.dev/docs/adapters) for your target environment. -->


# Todo App

## Introduction

Todo App is a simple task management application built that stores your daily tasks. You can create, update and delete your todos and manage your day-to-day activities efficiently.

## Tech Stack

+ [SvelteKit](https://kit.svelte.dev/) - Framework
+ [TypeScript](https://www.typescriptlang.org/) - Language
+ [Tailwind](https://tailwindcss.com/) - CSS
+ [Prisma](https://www.prisma.io/) - ORM
+ [Neon](https://neon.tech/) - Database
+ [Auth.js](https://authjs.dev/) - Auth
+ [Vercel](https://vercel.com/) - Hosting

## More about the app

Sign in to the app using your github account. Github OAuth token along with Auth.js is used for authentication. Task to be done and an image can be upload on the frontend which is built using Sveltekit along with Svelte ofcourse. Neon which is a serverless postgresql database is used to store the data. The schema's and API's of the app are defined using Prisma ORM. Tailwind is used for styling the frontend. Scripting is done with Typescript. Vercel is used deploy the app.