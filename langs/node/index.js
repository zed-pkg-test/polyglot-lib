// The Node slice of polyglot-lib. A consumer that installed the `-nodejs`
// package gets this file at its package root -- no sibling language packages beside
// it, because each language is published as its own artifact.
module.exports.greet = (who) => `hello ${who} from polyglot-lib/node`;
module.exports.LANGUAGE = "nodejs";
