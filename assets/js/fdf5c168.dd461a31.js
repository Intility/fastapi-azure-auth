"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[369],{3905:(e,t,n)=>{n.d(t,{Zo:()=>c,kt:()=>f});var a=n(7294);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},i=Object.keys(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var l=a.createContext({}),p=function(e){var t=a.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},c=function(e){var t=p(e.components);return a.createElement(l.Provider,{value:t},e.children)},u="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},m=a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,i=e.originalType,l=e.parentName,c=s(e,["components","mdxType","originalType","parentName"]),u=p(n),m=r,f=u["".concat(l,".").concat(m)]||u[m]||d[m]||i;return n?a.createElement(f,o(o({ref:t},c),{},{components:n})):a.createElement(f,o({ref:t},c))}));function f(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var i=n.length,o=new Array(i);o[0]=m;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[u]="string"==typeof e?e:r,o[1]=s;for(var p=2;p<i;p++)o[p]=n[p];return a.createElement.apply(null,o)}return a.createElement.apply(null,n)}m.displayName="MDXCreateElement"},3950:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>l,contentTitle:()=>o,default:()=>d,frontMatter:()=>i,metadata:()=>s,toc:()=>p});var a=n(7462),r=(n(7294),n(3905));const i={title:"Calling your APIs from Python",sidebar_position:4},o=void 0,s={unversionedId:"usage-and-faq/calling_your_apis_from_python",id:"usage-and-faq/calling_your_apis_from_python",title:"Calling your APIs from Python",description:"Azure setup",source:"@site/docs/usage-and-faq/calling_your_apis_from_python.mdx",sourceDirName:"usage-and-faq",slug:"/usage-and-faq/calling_your_apis_from_python",permalink:"/fastapi-azure-auth/usage-and-faq/calling_your_apis_from_python",editUrl:"https://github.com/Intility/FastAPI-Azure-Auth/edit/main/docs/docs/usage-and-faq/calling_your_apis_from_python.mdx",tags:[],version:"current",sidebarPosition:4,frontMatter:{title:"Calling your APIs from Python",sidebar_position:4},sidebar:"tutorialSidebar",previous:{title:"Locking down on roles",permalink:"/fastapi-azure-auth/usage-and-faq/locking_down_on_roles"},next:{title:"Using Microsoft Graph",permalink:"/fastapi-azure-auth/usage-and-faq/graph_usage"}},l={},p=[{value:"Azure setup",id:"azure-setup",level:2},{value:"FastAPI setup",id:"fastapi-setup",level:2},{value:"Single- and multi-tenant",id:"single--and-multi-tenant",level:3},{value:"B2C",id:"b2c",level:3}],c={toc:p},u="wrapper";function d(e){let{components:t,...i}=e;return(0,r.kt)(u,(0,a.Z)({},c,i,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("h2",{id:"azure-setup"},"Azure setup"),(0,r.kt)("p",null,"In order to call your APIs from Python (or any other backend), you should use the ",(0,r.kt)("a",{parentName:"p",href:"https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow"},"Client Credential Flow"),"."),(0,r.kt)("ol",null,(0,r.kt)("li",{parentName:"ol"},"Navigate to ",(0,r.kt)("a",{parentName:"li",href:"https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps"},"Azure -> Azure Active Directory -> App registrations"),"\nand find your ",(0,r.kt)("strong",{parentName:"li"},"OpenAPI application registration*")),(0,r.kt)("li",{parentName:"ol"},"Navigate over to ",(0,r.kt)("inlineCode",{parentName:"li"},"Certificate & secrets")),(0,r.kt)("li",{parentName:"ol"},"Click ",(0,r.kt)("inlineCode",{parentName:"li"},"New client secret")),(0,r.kt)("li",{parentName:"ol"},"Give it a name and an expiry time"),(0,r.kt)("li",{parentName:"ol"},"Click ",(0,r.kt)("inlineCode",{parentName:"li"},"Add"))),(0,r.kt)("div",{className:"admonition admonition-info alert alert--info"},(0,r.kt)("div",{parentName:"div",className:"admonition-heading"},(0,r.kt)("h5",{parentName:"div"},(0,r.kt)("span",{parentName:"h5",className:"admonition-icon"},(0,r.kt)("svg",{parentName:"span",xmlns:"http://www.w3.org/2000/svg",width:"14",height:"16",viewBox:"0 0 14 16"},(0,r.kt)("path",{parentName:"svg",fillRule:"evenodd",d:"M7 2.3c3.14 0 5.7 2.56 5.7 5.7s-2.56 5.7-5.7 5.7A5.71 5.71 0 0 1 1.3 8c0-3.14 2.56-5.7 5.7-5.7zM7 1C3.14 1 0 4.14 0 8s3.14 7 7 7 7-3.14 7-7-3.14-7-7-7zm1 3H6v5h2V4zm0 6H6v2h2v-2z"}))),"info")),(0,r.kt)("div",{parentName:"div",className:"admonition-content"},(0,r.kt)("p",{parentName:"div"},"In this example, we used the already created OpenAPI app registration in order to keep it short,\nbut in reality you should ",(0,r.kt)("strong",{parentName:"p"},"create a new app registration")," for ",(0,r.kt)("em",{parentName:"p"},"every")," application talking to your backend.\nIn other words, if someone wants to use your API, they should create their own app registration and their own secret."))),(0,r.kt)("p",null,(0,r.kt)("img",{loading:"lazy",alt:"secret_picture",src:n(9936).Z,width:"1687",height:"817"})),(0,r.kt)("div",{className:"admonition admonition-info alert alert--info"},(0,r.kt)("div",{parentName:"div",className:"admonition-heading"},(0,r.kt)("h5",{parentName:"div"},(0,r.kt)("span",{parentName:"h5",className:"admonition-icon"},(0,r.kt)("svg",{parentName:"span",xmlns:"http://www.w3.org/2000/svg",width:"14",height:"16",viewBox:"0 0 14 16"},(0,r.kt)("path",{parentName:"svg",fillRule:"evenodd",d:"M7 2.3c3.14 0 5.7 2.56 5.7 5.7s-2.56 5.7-5.7 5.7A5.71 5.71 0 0 1 1.3 8c0-3.14 2.56-5.7 5.7-5.7zM7 1C3.14 1 0 4.14 0 8s3.14 7 7 7 7-3.14 7-7-3.14-7-7-7zm1 3H6v5h2V4zm0 6H6v2h2v-2z"}))),"info")),(0,r.kt)("div",{parentName:"div",className:"admonition-content"},(0,r.kt)("p",{parentName:"div"},"You can use client certificates too, but we won't cover this here."))),(0,r.kt)("ol",{start:6},(0,r.kt)("li",{parentName:"ol"},"Copy the secret and save it for later.")),(0,r.kt)("p",null,(0,r.kt)("img",{loading:"lazy",alt:"copy_secret",src:n(4024).Z,width:"1019",height:"146"})),(0,r.kt)("h2",{id:"fastapi-setup"},"FastAPI setup"),(0,r.kt)("p",null,"The basic process is to first fetch the access token from Azure, and then call your own API endpoint."),(0,r.kt)("h3",{id:"single--and-multi-tenant"},"Single- and multi-tenant"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-python",metastring:'title="my_script.py"',title:'"my_script.py"'},"import asyncio\nfrom httpx import AsyncClient\nfrom demo_project.core.config import settings\n\nasync def main():\n    async with AsyncClient() as client:\n        azure_response = await client.post(\n            url=f'https://login.microsoftonline.com/{settings.TENANT_ID}/oauth2/v2.0/token',\n            data={\n                'grant_type': 'client_credentials',\n                'client_id': settings.OPENAPI_CLIENT_ID,  # the ID of the app reg you created the secret for\n                'client_secret': settings.CLIENT_SECRET,  # the secret you created\n                'scope': f'api://{settings.APP_CLIENT_ID}/.default',  # note: NOT .user_impersonation\n            }\n        )\n        token = azure_response.json()['access_token']\n\n        my_api_response = await client.get(\n            'http://localhost:8000/api/v1/hello-graph',\n            headers={'Authorization': f'Bearer {token}'},\n        )\n        print(my_api_response.json())\n\nif __name__ == '__main__':\n    asyncio.run(main())\n")),(0,r.kt)("h3",{id:"b2c"},"B2C"),(0,r.kt)("p",null,"Compared to the above, the only differences are the ",(0,r.kt)("inlineCode",{parentName:"p"},"scope")," and ",(0,r.kt)("inlineCode",{parentName:"p"},"url")," parameters:"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-python",metastring:'title="my_script.py"',title:'"my_script.py"'},"import asyncio\nfrom httpx import AsyncClient\nfrom demo_project.core.config import settings\n\nasync def main():\n    async with AsyncClient() as client:\n        azure_response = await client.post(\n            url=f'https://{settings.TENANT_NAME}.b2clogin.com/{settings.TENANT_NAME}.onmicrosoft.com/{settings.AUTH_POLICY_NAME}/oauth2/v2.0/token',\n            data={\n                'grant_type': 'client_credentials',\n                'client_id': settings.OPENAPI_CLIENT_ID,  # the ID of the app reg you created the secret for\n                'client_secret': settings.CLIENT_SECRET,  # the secret you created\n                'scope': f'https://{settings.TENANT_NAME}.onmicrosoft.com/{settings.APP_CLIENT_ID}/.default',\n            }\n        )\n        token = azure_response.json()['access_token']\n\n        my_api_response = await client.get(\n            'http://localhost:8000/api/v1/hello-graph',\n            headers={'Authorization': f'Bearer {token}'},\n        )\n        print(my_api_response.json())\n\nif __name__ == '__main__':\n    asyncio.run(main())\n\n")))}d.isMDXComponent=!0},4024:(e,t,n)=>{n.d(t,{Z:()=>a});const a=n.p+"assets/images/copy_secret-072e70a6c05d4b02eba87aead020c095.png"},9936:(e,t,n)=>{n.d(t,{Z:()=>a});const a=n.p+"assets/images/secret_picture-bff174b193d466b064a14fe6d405fd6a.png"}}]);