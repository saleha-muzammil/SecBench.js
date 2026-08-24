'use strict';

// Rebuild a constructor for a subclass from its parent class definition, so an inherited
// class keeps the parent's argument list and initialization body. `parent` is the parent
// class supplied by the caller via members.__parent.
module.exports = function inheritConstructor(parent) {
	var code = parent.toString();
	var args = code.substring(code.indexOf('(') + 1, code.indexOf(')'));
	var body = code.substring(code.indexOf('{') + 1, code.lastIndexOf('}'));
	var constructor;
	eval('constructor = function (' + args + ') {' + body + '};');
	return constructor;
};
