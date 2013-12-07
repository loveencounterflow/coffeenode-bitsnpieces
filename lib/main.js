(function() {
  var njs_path, validate_isa_number;

  njs_path = require('path');

  this.equals = function(a, b) {
    var assert, error;
    assert = require('assert');
    try {
      assert.deepEqual(a, b);
      return true;
    } catch (_error) {
      error = _error;
      return false;
    }
  };

  this.format_number = function(n) {
    var f, h;
    n = n.toString();
    f = function(n) {
      return h(n, /(\d+)(\d{3})/);
    };
    h = function(n, re) {
      while (re.test(n)) {
        n = n.replace(re, "$1" + "'" + "$2");
      }
      return n;
    };
    return f(n);
  };

  this.escape_regex = function(text) {

    /* Given a `text`, return the same with all regular expression metacharacters properly escaped. Escaped
    characters are `[]{}()*+?-.,\^$|#` plus whitespace.
     */
    return text.replace(/[-[\]{}()*+?.,\\\/^$|#\s]/g, "\\$&");
  };

  this.escape_html = function(text) {

    /* Given a `text`, return the same with all characters critical in HTML (`&`, `<`, `>`) properly
    escaped.
     */
    var R;
    R = text;
    R = R.replace(/&/g, '&amp;');
    R = R.replace(/</g, '&lt;');
    R = R.replace(/>/g, '&gt;');
    return R;
  };

  this.get_rnd = function(seed, delta) {
    var R;
    if (seed == null) {
      seed = 1;
    }
    if (delta == null) {
      delta = 1;
    }

    /*
    
    XXX This method returns a simple deterministic pseudo-random number generator—basically like
    `Math.random`, but (1) very probably with a much worse distribution of results, and (2) with predictable
    series of numbers, which is good for some testing scenarios. You may seed this method by passing in a
    `seed` and a `delta`, both of which must be non-zero numbers; the ensuing series of calls to the returned
    method will then always result in the same series of numbers. Here is a usage example that also shows how
    to reset the generator:
    
        BAP = require 'coffeenode-bitsnpieces'
        rnd = BAP.get_rnd() # or, say, `rnd = BAP.get_rnd 123, 0.5`
        log BAP.rnd() for idx in [ 0 .. 5 ]
        log()
        rnd.reset()
        log BAP.rnd() for idx in [ 0 .. 5 ]
    
    Please note that there are no strong guarantees made about the quality of the generated values except the
    (1) deterministic repeatability, (2) boundedness, and (3) 'apparent randomness'. Do **not** use this for
    cryptographic purposes.
     */
    R = function() {
      var x;
      R._idx += 1;
      x = (Math.sin(R._s)) * 10000;
      R._s += R._delta;
      return x - Math.floor(x);
    };
    R.reset = function(seed, delta) {

      /* Reset the generator. After calling `rnd.reset` (or `rnd.seed` with the same arguments), ensuing calls
      to `rnd` will always result in the same sequence of pseudo-random numbers.
       */
      if (seed == null) {
        seed = this._seed;
      }
      if (delta == null) {
        delta = this._delta;
      }
      validate_isa_number(seed);
      validate_isa_number(delta);
      if (seed === 0) {
        throw new Error("seed should not be zero");
      }
      if (delta === 0) {
        throw new Error("delta should not be zero");
      }
      R._s = seed;
      R._seed = seed;
      R._delta = delta;
      R._idx = -1;
      return null;
    };
    R.reset(seed, delta);
    return R;
  };


  /* TAINT code duplication (to avoid dependency on CoffeeNode Types). */

  validate_isa_number = function(x) {
    if (!((Object.prototype.toString.call(x)) === '[object Number]' && isFinite(x))) {
      throw "expected a number, got " + ((require('util')).inspect(x));
    }
  };

  this.pluck = function(x, name, fallback) {

    /* Given some object `x`, a `name` and a `fallback`, return the value of `x[ name ]`, or, if it does not
    exist, `fallback`. When the method returns, `x[ name ]` has been deleted.
     */
    var R;
    if (x[name] != null) {
      R = x[name];
      delete x[name];
    } else {
      R = fallback;
    }
    return R;
  };

  this.get_parent_routes = function(route) {
    var R;
    R = [];
    while (true) {
      R.push(route);
      if (route.length === 0 || route === '/') {
        break;
      }
      route = njs_path.dirname(route);
    }
    return R;
  };

  this.get_V8_CallSite_objects = function(delta) {
    var R, error, prepareStackTrace_original;
    if (delta == null) {
      delta = 0;
    }

    /* Save original Error.prepareStackTrace */
    prepareStackTrace_original = Error.prepareStackTrace;
    Error.prepareStackTrace = function(ignored, stack) {
      return stack;
    };
    error = new Error();
    R = error.stack;

    /* Restore original Error.prepareStackTrace */
    Error.prepareStackTrace = prepareStackTrace_original;
    delta += 1;
    if (delta !== 0) {
      R.splice(0, delta);
    }
    return R;
  };

  this.get_caller_info_stack = function(delta) {
    var R, call_sites, cs, entry, _i, _len;
    if (delta == null) {
      delta = 0;
    }
    call_sites = this.get_V8_CallSite_objects(delta + 1);
    R = [];
    for (_i = 0, _len = call_sites.length; _i < _len; _i++) {
      cs = call_sites[_i];
      entry = {
        'function-name': cs.getFunctionName(),
        'method-name': cs.getMethodName(),
        'filename': cs.getFileName(),
        'line-nr': cs.getLineNumber(),
        'column-nr': cs.getColumnNumber()
      };
      R.push(entry);
    }
    return R;
  };

  this.get_caller_routes = function(delta) {
    var call_sites, cs;
    if (delta == null) {
      delta = 0;
    }
    call_sites = this.get_V8_CallSite_objects(delta + 1);
    return (function() {
      var _i, _len, _results;
      _results = [];
      for (_i = 0, _len = call_sites.length; _i < _len; _i++) {
        cs = call_sites[_i];
        _results.push(cs.getFileName());
      }
      return _results;
    })();
  };

  this.get_filtered_caller_routes = function(delta) {
    var R, call_sites, cs, route, seen_routes, _i, _len;
    if (delta == null) {
      delta = 0;
    }
    call_sites = this.get_V8_CallSite_objects(delta + 1);
    seen_routes = {};
    R = [];
    for (_i = 0, _len = call_sites.length; _i < _len; _i++) {
      cs = call_sites[_i];
      route = cs.getFileName();

      /* ignore all duplicate routes: */
      if (seen_routes[route] != null) {
        continue;
      }
      seen_routes[route] = 1;

      /* ignore all 'internal' routes (these typically have no slash, other routes being absolute): */
      if ((route.indexOf('/')) === -1) {
        continue;
      }
      R.push(route);
    }
    return R;
  };

  this.create_id = function(values, length) {

    /* Given a number of `values` and a `length`, return an ID with `length` hexadecimal digits (`[0-9a-f]`)
    that deterministically depends on the input but can probably not reverse-engeneered to yield the input
    values. This is in no way meant to be cryptographically strong, just arbitrary enough so that we have a
    convenient method to derive an ID with little chance of overlap given different inputs. **Note** It is
    certainly possible to use this method (or `id_from_text`) to create a hash from a password to be stored in
    a DB. Don't do this. Use `bcrypt` or similar best-practices for password storage. Again, the intent of
    the BITSNPIECES ID utilities is *not* to be 'crypto-safe'; its intent is to give you a tool for generating
    repetition-free IDs.
     */
    var rpr, value;
    rpr = (require('util')).inspect;
    return this.id_from_text(((function() {
      var _i, _len, _results;
      _results = [];
      for (_i = 0, _len = values.length; _i < _len; _i++) {
        value = values[_i];
        _results.push(rpr(value));
      }
      return _results;
    })()).join('-'), length);
  };

  this.create_random_id = function(values, length) {

    /* Like `create_id`, but with an extra random factor built in that should exclude that two identical
    outputs are ever returned for any two identical inputs. Under the assumption that two calls to this
    method are highly unlikely two produce an identical pair `( 1 * new Date(), Math.random() )` (which could
    only happen if `Math.random()` returned the same number again *within the same clock millisecond*), and
    assuming you are using a reasonable value for `length` (i.e., say, `7 < length < 20`), you should never
    see the same ID twice.
     */
    values.push(1 * new Date() * Math.random());
    return this.create_id(values, length);
  };

  this.create_repeatable_random_id = function(values, length) {

    /* Like `create_random_id`, but with an extra random factor built in that should exclude that two identical
    outputs are ever returned for any two identical inputs. Under the assumption that two calls to this
    method are highly unlikely two produce an identical pair `( 1 * new Date(), Math.random() )` (which could
    only happen if `Math.random()` returned the same number again *within the same clock millisecond*), and
    assuming you are using a reasonable value for `length` (i.e., say, `7 < length < 20`), you should never
    see the same ID twice.
     */
    values.push(this.rn);
    return this.create_id(values, length);
  };

  this.id_from_text = function(text, length) {

    /* Given a `text` and a `length`, return an ID with `length` hexadecimal digits (`[0-9a-f]`)—this is like
    `create_id`, but working on a text rather than a number of arbitrary values. The hash algorithm currently
    used is SHA-1, which returns 40 hex digits; it should be good enough for the task at hand and has the
    advantage of being widely implemented.
     */

    /* TAINT should be a user option, or take 'good' algorithm universally available */
    var R;
    R = (((require('crypto')).createHash('sha1')).update(text, 'utf-8')).digest('hex');
    if (length != null) {
      return R.slice(0, length);
    } else {
      return R;
    }
  };

}).call(this);
/****generated by https://github.com/loveencounterflow/larq****/