"use strict";(self.webpackChunkdocs=self.webpackChunkdocs||[]).push([[568],{5680:(e,n,t)=>{t.d(n,{xA:()=>u,yg:()=>f});var r=t(6540);function a(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function o(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);n&&(r=r.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,r)}return t}function i(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?o(Object(t),!0).forEach((function(n){a(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function s(e,n){if(null==e)return{};var t,r,a=function(e,n){if(null==e)return{};var t,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||(a[t]=e[t]);return a}(e,n);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(a[t]=e[t])}return a}var l=r.createContext({}),p=function(e){var n=r.useContext(l),t=n;return e&&(t="function"==typeof e?e(n):i(i({},n),e)),t},u=function(e){var n=p(e.components);return r.createElement(l.Provider,{value:n},e.children)},c="mdxType",d={inlineCode:"code",wrapper:function(e){var n=e.children;return r.createElement(r.Fragment,{},n)}},m=r.forwardRef((function(e,n){var t=e.components,a=e.mdxType,o=e.originalType,l=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),c=p(t),m=a,f=c["".concat(l,".").concat(m)]||c[m]||d[m]||o;return t?r.createElement(f,i(i({ref:n},u),{},{components:t})):r.createElement(f,i({ref:n},u))}));function f(e,n){var t=arguments,a=n&&n.mdxType;if("string"==typeof e||a){var o=t.length,i=new Array(o);i[0]=m;var s={};for(var l in n)hasOwnProperty.call(n,l)&&(s[l]=n[l]);s.originalType=e,s[c]="string"==typeof e?e:a,i[1]=s;for(var p=2;p<o;p++)i[p]=t[p];return r.createElement.apply(null,i)}return r.createElement.apply(null,t)}m.displayName="MDXCreateElement"},9693:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>l,contentTitle:()=>i,default:()=>d,frontMatter:()=>o,metadata:()=>s,toc:()=>p});var r=t(8168),a=(t(6540),t(5680));const o={title:"Locking down on roles",sidebar_position:3},i=void 0,s={unversionedId:"usage-and-faq/locking_down_on_roles",id:"usage-and-faq/locking_down_on_roles",title:"Locking down on roles",description:"You can lock down on roles by creating your own wrapper dependency:",source:"@site/docs/usage-and-faq/locking_down_on_roles.mdx",sourceDirName:"usage-and-faq",slug:"/usage-and-faq/locking_down_on_roles",permalink:"/fastapi-azure-auth/usage-and-faq/locking_down_on_roles",editUrl:"https://github.com/Intility/FastAPI-Azure-Auth/edit/main/docs/docs/usage-and-faq/locking_down_on_roles.mdx",tags:[],version:"current",sidebarPosition:3,frontMatter:{title:"Locking down on roles",sidebar_position:3},sidebar:"tutorialSidebar",previous:{title:"Guest Users",permalink:"/fastapi-azure-auth/usage-and-faq/guest_users"},next:{title:"Calling your APIs from Python",permalink:"/fastapi-azure-auth/usage-and-faq/calling_your_apis_from_python"}},l={},p=[],u={toc:p},c="wrapper";function d(e){let{components:n,...t}=e;return(0,a.yg)(c,(0,r.A)({},u,t,{components:n,mdxType:"MDXLayout"}),(0,a.yg)("p",null,"You can lock down on roles by creating your own wrapper dependency:"),(0,a.yg)("pre",null,(0,a.yg)("code",{parentName:"pre",className:"language-python",metastring:'title="dependencies.py"',title:'"dependencies.py"'},'from fastapi import Depends\nfrom fastapi_azure_auth.exceptions import InvalidAuth\nfrom fastapi_azure_auth.user import User\n\nasync def validate_is_admin_user(user: User = Depends(azure_scheme)) -> None:\n    """\n    Validate that a user is in the `AdminUser` role in order to access the API.\n    Raises a 401 authentication error if not.\n    """\n    if \'AdminUser\' not in user.roles:\n        raise InvalidAuth(\'User is not an AdminUser\')\n')),(0,a.yg)("p",null,"and then use this dependency over ",(0,a.yg)("inlineCode",{parentName:"p"},"azure_scheme"),"."),(0,a.yg)("p",null,"Alternatively, after ",(0,a.yg)("a",{parentName:"p",href:"https://github.com/tiangolo/fastapi/releases/tag/0.95.0"},"FastAPI 0.95.0")," you can create an\n",(0,a.yg)("inlineCode",{parentName:"p"},"Annotated")," dependency."),(0,a.yg)("pre",null,(0,a.yg)("code",{parentName:"pre",className:"language-python",metastring:'title="security.py"',title:'"security.py"'},'from typing import Annotated\nfrom fastapi import Depends\nfrom fastapi_azure_auth.exceptions import InvalidAuth\nfrom fastapi_azure_auth.user import User\n\nasync def validate_is_admin_user(user: User = Depends(azure_scheme)) -> None:\n    """\n    Validate that a user is in the `AdminUser` role in order to access the API.\n    Raises a 401 authentication error if not.\n    """\n    if \'AdminUser\' not in user.roles:\n        raise InvalidAuth(\'User is not an AdminUser\')\n\nAdminUser = Annotated[User, Depends(validate_is_admin_user)]\n')),(0,a.yg)("p",null,"and in your view:"),(0,a.yg)("pre",null,(0,a.yg)("code",{parentName:"pre",className:"language-python",metastring:'title="my_view.py"',title:'"my_view.py"'},'@app.get("/items/")\ndef read_items(user: AdminUser):\n    ...\n')))}d.isMDXComponent=!0}}]);