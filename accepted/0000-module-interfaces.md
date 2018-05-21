# Module Interfaces

## Summary

A new feature allowing module authors to declare higher-risk Node.JS and browser APIs used by modules. This can then be verified by an `npm audit`-style feature in the npm client. Examples of interfaces might include:

- XMLHttpRequest (AJAX)
- fetch
- Navigator.mediaDevices (webcams, microphones)
- fs (Node.JS file system)
- eval

## Motivation

> There’s no shortage of smart, nasty people out there, and 580,000 npm packages. It seems to me that the odds are better than even that at least one of those packages has some malicious code in it, and that if it’s done well, you would never even know.

[David Gilbertson's article](https://hackernoon.com/im-harvesting-credit-card-numbers-and-passwords-from-your-site-here-s-how-9a8cb347c5b5) highlighted a widespread anxiety among developers that it can be hard to know what the npm modules in your codebase are actually doing. The post posited (albeit fictiously) that the author had created a package that sends sensitive data to their server for malicious uses, posing as a package for formatting console messages.

The fictious package gathers data from forms (using `document.forms`), cookies (`document.cookies`) and posts it to the server using `EventSource`. Use of these interfaces by such a module would normally be unthinkable. Surfacing this information to developers could ease their anxiety and allow them to make informed decisions when choosing a module to install.

## Detailed Explanation

Interfaces are declared by package authors in the `package.json` file using a new `interfaces` key. This is an array of string objects that describe the interfaces the package uses:

```
{
  ...
  interfaces: [
    'XMLHttpRequest',
    'fetch'
  ]
}
```

A new npm feature, similar to `npm audit`, could then be used by the end user to verify that each dependency complies with its named interfaces. Any dependencies using interfaces not named in their package.json will be reported to the end user.

Interfaces could also be listed on the [npmjs.com](http://npmjs.com) website to surface this information to users selecting packages to install into their projects. Other parties might also be interested in consuming this information. [webpack](https://webpack.js.org/) may be interested in using named interfaces to transcode calls to high-risk APIs at build-time to control their usage.

## Rationale and Alternatives

### Auditing service

Alternatively, a service could be employed to verify modules for their compliance when they are published. Such a feature would benefit a larger number of users, because potentially all packages could be checked before they are published.

However, introspecting the amount of packages that are published to the npm registry may be prohibitively expensive in terms of performance. Package publishers may be willing to pay a premium for a checkmark on their package page verifying that their package has been audited by npm.

### Transcoding source at install time

Instead of auditing the source code, it may be possible to provide an option to transcode modules when they are installed. This process would not just identify calls to risky APIs, it would re-write the calls completely. This would provide further assurance that high-risk APIs could not be used by packages unless explicitly declared.

It seems unlikely that this would be a useful feature. npm is expected to install the _exact same_ package as published, and this is a useful quality for ensuring packages are delivered from publisher to user securely. However, this may be a feature that projects such as [webpack](https://webpack.js.org/) may be interested in implementing.

## Implementation

I have created a proof of concept for an auditing tool based on a [babel](https://babeljs.io/) plugin. The plugin introspects `CallExpression` and `MemberExpression` expressions to gather information about APIs a file is calling.

A `CallExpression` visitor is used to find function calls to [require](https://nodejs.org/api/modules.html#modules_require) that contain the string `"fs"`. This can be used to find calls to the [Node.JS fs api](https://nodejs.org/api/fs.html).

A `MemberExpression` visitor is used to find member calls to the `window` object that access the `XMLHttpRequest` member. This can be used to find calls to the [AJAX browser API](https://developer.mozilla.org/en-US/docs/Web/Guide/AJAX).

The proof of concept exits with exit status 1 if such calls are found. Further work could be undertaken to:

- Identify uses of these APIs which access them using alternative methods, such as accessing `XMLHttpRequest` as a global instead as a member of the `window` object.
- Create new visitors to detect uses of other risky APIs, such as `fetch`.
- Add a feature to enable and disable visitors based on which interfaces are declared in `package.json`.

### Auditing obfuscated code

Obfuscated calls to risky APIs pose a problem for an auditing feature. For example, take the following expression:

`window['YMLHttpRequest'.replace('Y', 'X')]`

This expression accesses the `XMLHttpRequest` API without explicitly referencing it by its name in code. We can expect more elaborate attempts by publishers to circumvent auditing to provide false assurances to users installing their modules. Framing this feature as a cast-iron assurance to users may result in arms-race with ill-meaning publishers as new ways of defeating the auditing process are discovered.

This could potentially be addressed by creating visitors to identify expressions dynamically accessing members of the `window` object. The proof of concept includes visitors to find member expressions that include non-string property nodes, as seen in the above example (n.b. `'YMLHttpRequest'.replace('Y', 'X')` evaluates to a string in JS, but it is considered a `CallExpression` by babel).

Detection of obfuscated code may be an unnecessary feature if it can be detected by linters such as [ESLint](https://eslint.org/). This may be desirable if it is decided that detecting obfuscated code is too big a problem for auditing to solve.

### Alternatives to babel
[babel-cli](https://www.npmjs.com/package/babel-cli), used by the proof-of-concept, is a heavyweight dependency at 23Mb in size. This feature could be implemented with an alternative, lighter-weight parser.

## Prior Art

The [snapcraft](https://snapcraft.io/) package manager [advertises interfaces](https://docs.snapcraft.io/core/interfaces) as a headline feature. It can offer robust isolation of risky APIs because snaps are encapsulated inside [Linux Containers](https://en.wikipedia.org/wiki/LXC). A full list of snapcraft interfaces can be found in the [interfaces reference page](https://docs.snapcraft.io/reference/interfaces).

## Supporting material
### Proof of concept source

```
module.exports = function({ types: t }) {
 return {
   visitor: {
     CallExpression(path, state) {
       if (path.node.callee.name === 'require') {
         if (path.node.arguments[0].value === 'fs') {
           console.log('Error: Forbidden use of Node "fs" interface')
           process.exit(1)
         }
         if (path.node.arguments[0].type !== 'StringLiteral') {
           console.log('Error: Forbidden use of dynamic module loading')
           process.exit(1)
         }
       }
     },
     MemberExpression(path, state) {
       if (
         path.node.object.name === 'window'
         && path.node.property
         && path.node.property.type !== 'StringLiteral')
       {
         console.log('KF: blah: ', path.node.property.type)
         console.log('Error: Forbidden dynamic access of window properties')
         process.exit(1)
       }
       if (
         path.node.object.name === 'window'
         && path.node.property
         && path.node.property.value == 'XMLHttpRequest')
       {
         console.log('Error: Forbidden use of XMLHttpRequest')
         process.exit(1)
       }
     }
   }
 };
};
```
