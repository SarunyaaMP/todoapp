import{s as d,a as p,u as h,g,b,c as v}from"../chunks/scheduler.Rzn6huuy.js";import{S as y,i as $,e as u,s as k,c as m,a as H,f as x,d as f,l as L,g as _,h as C,m as M,n as P,k as S}from"../chunks/index.D6xxGKKq.js";import{p as T}from"../chunks/stores.BHG8Ifde.js";function c(i){let e,n='<h2><a href="/" class="text-sm text-center text-gray-800 md:text-lg">Home Page</a></h2>';return{c(){e=u("hgroup"),e.innerHTML=n},l(l){e=m(l,"HGROUP",{"data-svelte-h":!0}),S(e)!=="svelte-1mybkef"&&(e.innerHTML=n)},m(l,t){_(l,e,t)},d(l){l&&f(e)}}}function q(i){let e,n,l,t=i[0].data.session&&c();const r=i[2].default,s=p(r,i,i[1],null);return{c(){e=u("div"),t&&t.c(),n=k(),s&&s.c(),this.h()},l(a){e=m(a,"DIV",{class:!0});var o=H(e);t&&t.l(o),n=x(o),s&&s.l(o),o.forEach(f),this.h()},h(){L(e,"class","container mx-auto my-6 max-w-lg")},m(a,o){_(a,e,o),t&&t.m(e,null),C(e,n),s&&s.m(e,null),l=!0},p(a,[o]){a[0].data.session?t||(t=c(),t.c(),t.m(e,n)):t&&(t.d(1),t=null),s&&s.p&&(!l||o&2)&&h(s,r,a,a[1],l?b(r,a[1],o,null):g(a[1]),null)},i(a){l||(M(s,a),l=!0)},o(a){P(s,a),l=!1},d(a){a&&f(e),t&&t.d(),s&&s.d(a)}}}function w(i,e,n){let l;v(i,T,s=>n(0,l=s));let{$$slots:t={},$$scope:r}=e;return i.$$set=s=>{"$$scope"in s&&n(1,r=s.$$scope)},[l,r,t]}class I extends y{constructor(e){super(),$(this,e,w,q,d,{})}}export{I as component};
