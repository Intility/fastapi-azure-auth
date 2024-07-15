"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[200],{5680:(e,t,n)=>{n.d(t,{xA:()=>c,yg:()=>y});var a=n(6540);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function r(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function p(e,t){if(null==e)return{};var n,a,i=function(e,t){if(null==e)return{};var n,a,i={},o=Object.keys(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||(i[n]=e[n]);return i}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(i[n]=e[n])}return i}var l=a.createContext({}),s=function(e){var t=a.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):r(r({},t),e)),n},c=function(e){var t=s(e.components);return a.createElement(l.Provider,{value:t},e.children)},g="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},u=a.forwardRef((function(e,t){var n=e.components,i=e.mdxType,o=e.originalType,l=e.parentName,c=p(e,["components","mdxType","originalType","parentName"]),g=s(n),u=i,y=g["".concat(l,".").concat(u)]||g[u]||d[u]||o;return n?a.createElement(y,r(r({ref:t},c),{},{components:n})):a.createElement(y,r({ref:t},c))}));function y(e,t){var n=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var o=n.length,r=new Array(o);r[0]=u;var p={};for(var l in t)hasOwnProperty.call(t,l)&&(p[l]=t[l]);p.originalType=e,p[g]="string"==typeof e?e:i,r[1]=p;for(var s=2;s<o;s++)r[s]=n[s];return a.createElement.apply(null,r)}return a.createElement.apply(null,n)}u.displayName="MDXCreateElement"},2050:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>l,contentTitle:()=>r,default:()=>d,frontMatter:()=>o,metadata:()=>p,toc:()=>s});var a=n(8168),i=(n(6540),n(5680));const o={title:"Azure configuration",sidebar_position:1},r=void 0,p={unversionedId:"multi-tenant/azure_setup",id:"multi-tenant/azure_setup",title:"Azure configuration",description:"We'll need to create two application registrations for Azure AD authentication to cover both direct API",source:"@site/docs/multi-tenant/azure_setup.mdx",sourceDirName:"multi-tenant",slug:"/multi-tenant/azure_setup",permalink:"/fastapi-azure-auth/multi-tenant/azure_setup",editUrl:"https://github.com/Intility/FastAPI-Azure-Auth/edit/main/docs/docs/multi-tenant/azure_setup.mdx",tags:[],version:"current",sidebarPosition:1,frontMatter:{title:"Azure configuration",sidebar_position:1},sidebar:"tutorialSidebar",previous:{title:"FastAPI configuration",permalink:"/fastapi-azure-auth/single-tenant/fastapi_configuration"},next:{title:"FastAPI configuration",permalink:"/fastapi-azure-auth/multi-tenant/fastapi_configuration"}},l={},s=[{value:"Backend API",id:"backend-api",level:2},{value:"Step 1 - Create app registration",id:"step-1---create-app-registration",level:3},{value:"Step 2 - Change token version to <code>v2</code>",id:"step-2---change-token-version-to-v2",level:3},{value:"Step 3 - Note down your application IDs",id:"step-3---note-down-your-application-ids",level:3},{value:"Step 4 - Add an application scope",id:"step-4---add-an-application-scope",level:3},{value:"OpenAPI Documentation",id:"openapi-documentation",level:2},{value:"Step 1 - Create app registration",id:"step-1---create-app-registration-1",level:3},{value:"Step 2 - Change token version to <code>v2</code>",id:"step-2---change-token-version-to-v2-1",level:3},{value:"Step 3 - Note down your application IDs",id:"step-3---note-down-your-application-ids-1",level:3},{value:"Step 4 - Allow OpenAPI to talk to the backend",id:"step-4---allow-openapi-to-talk-to-the-backend",level:3}],c={toc:s},g="wrapper";function d(e){let{components:t,...o}=e;return(0,i.yg)(g,(0,a.A)({},c,o,{components:t,mdxType:"MDXLayout"}),(0,i.yg)("p",null,"We'll need to create two application registrations for Azure AD authentication to cover both direct API\nuse and usage from the OpenAPI (swagger) documentation."),(0,i.yg)("p",null,"We'll start with the API."),(0,i.yg)("h2",{id:"backend-api"},"Backend API"),(0,i.yg)("h3",{id:"step-1---create-app-registration"},"Step 1 - Create app registration"),(0,i.yg)("p",null,"Head over to\n",(0,i.yg)("a",{parentName:"p",href:"https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps"},"Azure -> Azure Active Directory -> App registrations"),",\nand create a new registration."),(0,i.yg)("p",null,"Select a fitting name for your project; Azure will present the name to the user during consent."),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("inlineCode",{parentName:"li"},"Supported account types"),": ",(0,i.yg)("inlineCode",{parentName:"li"},"Multitenant")," -  If you want to create a multi-tenant application, you\nshould head over to the ",(0,i.yg)("a",{parentName:"li",href:"/fastapi-azure-auth/multi-tenant/azure_setup"},"multi-tenant documentation"))),(0,i.yg)("p",null,(0,i.yg)("img",{loading:"lazy",alt:"1_application_registration",src:n(5318).A,width:"891",height:"608"})),(0,i.yg)("p",null,"Press ",(0,i.yg)("strong",{parentName:"p"},"Register")),(0,i.yg)("h3",{id:"step-2---change-token-version-to-v2"},"Step 2 - Change token version to ",(0,i.yg)("inlineCode",{parentName:"h3"},"v2")),(0,i.yg)("p",null,"First we'll change the token version to version 2. In the left menu bar, click ",(0,i.yg)("inlineCode",{parentName:"p"},"Manifest")," and find the line\nthat says ",(0,i.yg)("inlineCode",{parentName:"p"},"accessTokenAcceptedVersion"),". Change its value from ",(0,i.yg)("inlineCode",{parentName:"p"},"null")," to ",(0,i.yg)("inlineCode",{parentName:"p"},"2"),"."),(0,i.yg)("p",null,(0,i.yg)("img",{loading:"lazy",alt:"2_manifest",src:n(1193).A,width:"806",height:"509"})),(0,i.yg)("p",null,"Press ",(0,i.yg)("strong",{parentName:"p"},"Save")),(0,i.yg)("p",null,"(This change can take some time to happen, which is why we do this first.)"),(0,i.yg)("h3",{id:"step-3---note-down-your-application-ids"},"Step 3 - Note down your application IDs"),(0,i.yg)("p",null,"Go back to the ",(0,i.yg)("inlineCode",{parentName:"p"},"Overview"),", found in the left menu."),(0,i.yg)("p",null,(0,i.yg)("img",{loading:"lazy",alt:"3_overview",src:n(6815).A,width:"810",height:"357"})),(0,i.yg)("p",null,"Copy the ",(0,i.yg)("inlineCode",{parentName:"p"},"Application (Client) ID"),", we'll need that for later. I like to use ",(0,i.yg)("inlineCode",{parentName:"p"},".env")," files to\nstore variables like these:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-bash",metastring:'title=".env"',title:'".env"'},"APP_CLIENT_ID=\n")),(0,i.yg)("h3",{id:"step-4---add-an-application-scope"},"Step 4 - Add an application scope"),(0,i.yg)("ol",null,(0,i.yg)("li",{parentName:"ol"},"Go to ",(0,i.yg)("strong",{parentName:"li"},"Expose an API")," in the left menu bar under your app registration."),(0,i.yg)("li",{parentName:"ol"},"Press ",(0,i.yg)("strong",{parentName:"li"},"+ Add a scope")),(0,i.yg)("li",{parentName:"ol"},"Press ",(0,i.yg)("strong",{parentName:"li"},"Save and continue"))),(0,i.yg)("p",null,(0,i.yg)("img",{loading:"lazy",alt:"4_add_scope",src:n(51).A,width:"1215",height:"425"})),(0,i.yg)("p",null,"Add a scope named ",(0,i.yg)("inlineCode",{parentName:"p"},"user_impersonation")," that can be consented by ",(0,i.yg)("inlineCode",{parentName:"p"},"Admins and users"),".\n",(0,i.yg)("img",{loading:"lazy",alt:"5_add_scope_props",src:n(6901).A,width:"583",height:"735"})),(0,i.yg)("p",null,"You can use the following descriptions:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-text"},"Access API as user\nAllows the app to access the API as the user.\n\nAccess API as you\nAllows the app to access the API as you.\n")),(0,i.yg)("h2",{id:"openapi-documentation"},"OpenAPI Documentation"),(0,i.yg)("p",null,"Our OpenAPI documentation will use the ",(0,i.yg)("inlineCode",{parentName:"p"},"Authorization Code Grant Flow, with Proof Key for Code Exchange")," flow.\nIt's a flow that enables a user of a Single-Page Application to safely log in, consent to permissions and fetch an ",(0,i.yg)("inlineCode",{parentName:"p"},"access_token"),"\nin the ",(0,i.yg)("inlineCode",{parentName:"p"},"JWT")," format. When the user clicks ",(0,i.yg)("inlineCode",{parentName:"p"},"Try out")," on the APIs, the ",(0,i.yg)("inlineCode",{parentName:"p"},"access_token")," is attached to the header as a ",(0,i.yg)("inlineCode",{parentName:"p"},"Bearer ")," token.\nThis is the token the backend will validate."),(0,i.yg)("p",null,"So, let's set it up!"),(0,i.yg)("h3",{id:"step-1---create-app-registration-1"},"Step 1 - Create app registration"),(0,i.yg)("p",null,"Just like in the previous chapter, we have to create an application registration for our OpenAPI."),(0,i.yg)("p",null,"Head over to\n",(0,i.yg)("a",{parentName:"p",href:"https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps"},"Azure -> Azure Active Directory -> App registrations"),",\nand create a new registration."),(0,i.yg)("p",null,"Use the same name, but with ",(0,i.yg)("inlineCode",{parentName:"p"},"- OpenAPI")," appended to it."),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("inlineCode",{parentName:"li"},"Supported account types"),": ",(0,i.yg)("inlineCode",{parentName:"li"},"Multitenant")),(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("inlineCode",{parentName:"li"},"Redirect URI"),": Choose ",(0,i.yg)("inlineCode",{parentName:"li"},"Single-Page Application (SPA)")," and ",(0,i.yg)("inlineCode",{parentName:"li"},"http://localhost:8000/oauth2-redirect")," as a value")),(0,i.yg)("p",null,(0,i.yg)("img",{loading:"lazy",alt:"6_application_registration_openapi",src:n(446).A,width:"932",height:"632"})),(0,i.yg)("p",null,"Press ",(0,i.yg)("strong",{parentName:"p"},"Register")),(0,i.yg)("h3",{id:"step-2---change-token-version-to-v2-1"},"Step 2 - Change token version to ",(0,i.yg)("inlineCode",{parentName:"h3"},"v2")),(0,i.yg)("p",null,"Like last time, we'll change the token version to version 2. In the left menu bar, click ",(0,i.yg)("inlineCode",{parentName:"p"},"Manifest")," and find the line\nthat says ",(0,i.yg)("inlineCode",{parentName:"p"},"accessTokenAcceptedVersion"),". Change its value from ",(0,i.yg)("inlineCode",{parentName:"p"},"null")," to ",(0,i.yg)("inlineCode",{parentName:"p"},"2"),"."),(0,i.yg)("p",null,(0,i.yg)("img",{loading:"lazy",alt:"3_manifest",src:n(1193).A,width:"806",height:"509"})),(0,i.yg)("p",null,"Press ",(0,i.yg)("strong",{parentName:"p"},"Save")),(0,i.yg)("h3",{id:"step-3---note-down-your-application-ids-1"},"Step 3 - Note down your application IDs"),(0,i.yg)("p",null,"You should now be redirected to the ",(0,i.yg)("inlineCode",{parentName:"p"},"Overview"),"."),(0,i.yg)("p",null,(0,i.yg)("img",{loading:"lazy",alt:"7_overview_openapi",src:n(9810).A,width:"1546",height:"189"})),(0,i.yg)("p",null,"Copy the ",(0,i.yg)("inlineCode",{parentName:"p"},"Application (Client) ID")," and save it as your ",(0,i.yg)("inlineCode",{parentName:"p"},"OPENAPI_CLIENT_ID"),":"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-bash",metastring:'title=".env" {2}',title:'".env"',"{2}":!0},"APP_CLIENT_ID=\nOPENAPI_CLIENT_ID=\n")),(0,i.yg)("h3",{id:"step-4---allow-openapi-to-talk-to-the-backend"},"Step 4 - Allow OpenAPI to talk to the backend"),(0,i.yg)("p",null,"To allow OpenAPI to talk to the backend API, you must add API permissions to the OpenAPI app registration.\nIn the left menu, go to ",(0,i.yg)("strong",{parentName:"p"},"API Permissions")," and ",(0,i.yg)("strong",{parentName:"p"},"Add a permission"),"."),(0,i.yg)("p",null,(0,i.yg)("img",{loading:"lazy",alt:"8_api_permissions",src:n(3142).A,width:"1090",height:"753"})),(0,i.yg)("p",null,"Select the ",(0,i.yg)("inlineCode",{parentName:"p"},"user_impersonation")," scope, and press ",(0,i.yg)("strong",{parentName:"p"},"Add a permission"),"."),(0,i.yg)("p",null,"Your view should now look something like this:"),(0,i.yg)("p",null,(0,i.yg)("img",{loading:"lazy",alt:"9_api_permissions_finish",src:n(8561).A,width:"1037",height:"184"})),(0,i.yg)("p",null,"That's it! Next step is to configure the FastAPI application."))}d.isMDXComponent=!0},5318:(e,t,n)=>{n.d(t,{A:()=>a});const a=n.p+"assets/images/1_application_registration-08a8c9f21a45b6d578d8d15631946edf.png"},6815:(e,t,n)=>{n.d(t,{A:()=>a});const a=n.p+"assets/images/3_overview-1e1a668b849eaf31ce7b058e64bf0660.png"},51:(e,t,n)=>{n.d(t,{A:()=>a});const a=n.p+"assets/images/4_add_scope-575b44371cf4e5e81231943a741d34c5.png"},6901:(e,t,n)=>{n.d(t,{A:()=>a});const a=n.p+"assets/images/5_add_scope_props-840ca51c787286fc24e65ae01049920a.png"},446:(e,t,n)=>{n.d(t,{A:()=>a});const a=n.p+"assets/images/6_application_registration_openapi-ec97c895923720a777cce453ed591161.png"},9810:(e,t,n)=>{n.d(t,{A:()=>a});const a=n.p+"assets/images/7_overview_openapi-7c3d17d5eb24caedf1269daba48b8b6c.png"},3142:(e,t,n)=>{n.d(t,{A:()=>a});const a=n.p+"assets/images/8_api_permissions-8c47c586e9521d5e897fc1884b82ab1a.png"},8561:(e,t,n)=>{n.d(t,{A:()=>a});const a=n.p+"assets/images/9_api_permissions_finish-48d03b99688420c25d45a2bb31569f34.png"},1193:(e,t,n)=>{n.d(t,{A:()=>a});const a=n.p+"assets/images/2_manifest-1b8787c29ab4f1141631adc9b0e1f6da.png"}}]);