(()=>{"use strict";var e,t,r,a,o,d={},c={};function n(e){var t=c[e];if(void 0!==t)return t.exports;var r=c[e]={id:e,loaded:!1,exports:{}};return d[e].call(r.exports,r,r.exports,n),r.loaded=!0,r.exports}n.m=d,n.c=c,e=[],n.O=(t,r,a,o)=>{if(!r){var d=1/0;for(i=0;i<e.length;i++){r=e[i][0],a=e[i][1],o=e[i][2];for(var c=!0,f=0;f<r.length;f++)(!1&o||d>=o)&&Object.keys(n.O).every((e=>n.O[e](r[f])))?r.splice(f--,1):(c=!1,o<d&&(d=o));if(c){e.splice(i--,1);var b=a();void 0!==b&&(t=b)}}return t}o=o||0;for(var i=e.length;i>0&&e[i-1][2]>o;i--)e[i]=e[i-1];e[i]=[r,a,o]},n.n=e=>{var t=e&&e.__esModule?()=>e.default:()=>e;return n.d(t,{a:t}),t},r=Object.getPrototypeOf?e=>Object.getPrototypeOf(e):e=>e.__proto__,n.t=function(e,a){if(1&a&&(e=this(e)),8&a)return e;if("object"==typeof e&&e){if(4&a&&e.__esModule)return e;if(16&a&&"function"==typeof e.then)return e}var o=Object.create(null);n.r(o);var d={};t=t||[null,r({}),r([]),r(r)];for(var c=2&a&&e;"object"==typeof c&&!~t.indexOf(c);c=r(c))Object.getOwnPropertyNames(c).forEach((t=>d[t]=()=>e[t]));return d.default=()=>e,n.d(o,d),o},n.d=(e,t)=>{for(var r in t)n.o(t,r)&&!n.o(e,r)&&Object.defineProperty(e,r,{enumerable:!0,get:t[r]})},n.f={},n.e=e=>Promise.all(Object.keys(n.f).reduce(((t,r)=>(n.f[r](e,t),t)),[])),n.u=e=>"assets/js/"+({50:"0b387740",66:"972d9d57",98:"b5a82c26",145:"9dcf1fd7",200:"94d9bb9b",283:"77c04317",303:"4338ef83",351:"bccea385",401:"17896441",431:"b7b10d73",498:"1d3e3128",545:"8641a95d",568:"1ad6a286",693:"5964223c",711:"9e4087bc",714:"1be78505",732:"0e0048d6",801:"624fcd96",802:"fa4d91bf",845:"9a65b867",870:"a633a1c5",943:"e281ba72",963:"670d863f",981:"4640ce17",992:"fdf5c168"}[e]||e)+"."+{37:"52ef839e",50:"bab59d64",66:"413dc4af",90:"7b373ad5",98:"7405c1e5",145:"a47485ae",200:"2cc98020",278:"555b608f",283:"de6cd446",303:"78f88ac1",351:"e6a5a91e",401:"f1877f92",431:"0baffd97",498:"fd69319d",545:"090c2293",568:"e8185c31",577:"307cfa84",693:"50cb9e0d",711:"30d5cc62",714:"e0b86e78",732:"dd6d02cf",801:"cbb8f338",802:"1675965d",845:"6737f2fe",854:"97b87711",870:"2901cdc8",943:"f1dedfd3",963:"37bdd5fe",981:"7f06f985",992:"02866f02"}[e]+".js",n.miniCssF=e=>{},n.g=function(){if("object"==typeof globalThis)return globalThis;try{return this||new Function("return this")()}catch(e){if("object"==typeof window)return window}}(),n.o=(e,t)=>Object.prototype.hasOwnProperty.call(e,t),a={},o="docs:",n.l=(e,t,r,d)=>{if(a[e])a[e].push(t);else{var c,f;if(void 0!==r)for(var b=document.getElementsByTagName("script"),i=0;i<b.length;i++){var u=b[i];if(u.getAttribute("src")==e||u.getAttribute("data-webpack")==o+r){c=u;break}}c||(f=!0,(c=document.createElement("script")).charset="utf-8",c.timeout=120,n.nc&&c.setAttribute("nonce",n.nc),c.setAttribute("data-webpack",o+r),c.src=e),a[e]=[t];var l=(t,r)=>{c.onerror=c.onload=null,clearTimeout(s);var o=a[e];if(delete a[e],c.parentNode&&c.parentNode.removeChild(c),o&&o.forEach((e=>e(r))),t)return t(r)},s=setTimeout(l.bind(null,void 0,{type:"timeout",target:c}),12e4);c.onerror=l.bind(null,c.onerror),c.onload=l.bind(null,c.onload),f&&document.head.appendChild(c)}},n.r=e=>{"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},n.p="/fastapi-azure-auth/",n.gca=function(e){return e={17896441:"401","0b387740":"50","972d9d57":"66",b5a82c26:"98","9dcf1fd7":"145","94d9bb9b":"200","77c04317":"283","4338ef83":"303",bccea385:"351",b7b10d73:"431","1d3e3128":"498","8641a95d":"545","1ad6a286":"568","5964223c":"693","9e4087bc":"711","1be78505":"714","0e0048d6":"732","624fcd96":"801",fa4d91bf:"802","9a65b867":"845",a633a1c5:"870",e281ba72:"943","670d863f":"963","4640ce17":"981",fdf5c168:"992"}[e]||e,n.p+n.u(e)},(()=>{var e={354:0,869:0};n.f.j=(t,r)=>{var a=n.o(e,t)?e[t]:void 0;if(0!==a)if(a)r.push(a[2]);else if(/^(354|869)$/.test(t))e[t]=0;else{var o=new Promise(((r,o)=>a=e[t]=[r,o]));r.push(a[2]=o);var d=n.p+n.u(t),c=new Error;n.l(d,(r=>{if(n.o(e,t)&&(0!==(a=e[t])&&(e[t]=void 0),a)){var o=r&&("load"===r.type?"missing":r.type),d=r&&r.target&&r.target.src;c.message="Loading chunk "+t+" failed.\n("+o+": "+d+")",c.name="ChunkLoadError",c.type=o,c.request=d,a[1](c)}}),"chunk-"+t,t)}},n.O.j=t=>0===e[t];var t=(t,r)=>{var a,o,d=r[0],c=r[1],f=r[2],b=0;if(d.some((t=>0!==e[t]))){for(a in c)n.o(c,a)&&(n.m[a]=c[a]);if(f)var i=f(n)}for(t&&t(r);b<d.length;b++)o=d[b],n.o(e,o)&&e[o]&&e[o][0](),e[o]=0;return n.O(i)},r=self.webpackChunkdocs=self.webpackChunkdocs||[];r.forEach(t.bind(null,0)),r.push=t.bind(null,r.push.bind(r))})()})();