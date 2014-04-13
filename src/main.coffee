

############################################################################################################
njs_path                  = require 'path'




#-----------------------------------------------------------------------------------------------------------
@equals = ( a, b ) ->
  ### `equals` is a shim for accessing the NodeJS `assert.deepEqual` method. Use it for PODs and lists. ###
  assert = require 'assert'
  try
    assert.deepEqual a, b
    return true
  catch error
    return false

#-----------------------------------------------------------------------------------------------------------
@format_number = ( n ) ->
  ### A simple number formatter. ###
  n       = n.toString()
  f       = ( n ) -> return h n, /(\d+)(\d{3})/
  h       = ( n, re ) -> n = n.replace re, "$1" + "'" + "$2" while re.test n; return n
  return f n

#-----------------------------------------------------------------------------------------------------------
@escape_regex = ( text ) ->
  ### Given a `text`, return the same with all regular expression metacharacters properly escaped. Escaped
  characters are `[]{}()*+?-.,\^$|#` plus whitespace. ###
  #.........................................................................................................
  return text.replace /[-[\]{}()*+?.,\\\/^$|#\s]/g, "\\$&"

#-----------------------------------------------------------------------------------------------------------
@escape_html = ( text ) ->
  ### Given a `text`, return the same with all characters critical in HTML (`&`, `<`, `>`) properly
  escaped. ###
  R = text
  R = R.replace /&/g, '&amp;'
  R = R.replace /</g, '&lt;'
  R = R.replace />/g, '&gt;'
  #.........................................................................................................
  return R


#===========================================================================================================
# RANDOM NUMBERS
#-----------------------------------------------------------------------------------------------------------
@get_rnd = ( seed = 1, delta = 1 ) ->
  ### This method returns a simple deterministic pseudo-random number generator—basically like
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
  cryptographic purposes. ###
  #.........................................................................................................
  R = ->
    R._idx  += 1
    x       = ( Math.sin R._s ) * 10000
    R._s    += R._delta
    return x - Math.floor x
  #.........................................................................................................
  R.reset = ( seed, delta ) ->
    ### Reset the generator. After calling `rnd.reset` (or `rnd.seed` with the same arguments), ensuing calls
    to `rnd` will always result in the same sequence of pseudo-random numbers. ###
    seed   ?= @._seed
    delta  ?= @._delta
    #.......................................................................................................
    validate_isa_number seed
    validate_isa_number delta
    #.......................................................................................................
    throw new Error "seed should not be zero"  unless seed  != 0
    throw new Error "delta should not be zero" unless delta != 0
    #.......................................................................................................
    R._s     = seed
    R._seed  = seed
    R._delta = delta
    R._idx   = -1
    return null
  #.........................................................................................................
  R.reset seed, delta
  #.........................................................................................................
  return R


#-----------------------------------------------------------------------------------------------------------
### TAINT code duplication (to avoid dependency on CoffeeNode Types). ###
validate_isa_number = ( x ) ->
  unless ( Object::toString.call x ) == '[object Number]' and isFinite x
    throw "expected a number, got #{( require 'util' ).inspect x}"


#===========================================================================================================
# PODs
#-----------------------------------------------------------------------------------------------------------
@pluck = ( x, name, fallback ) ->
  ### Given some object `x`, a `name` and a `fallback`, return the value of `x[ name ]`, or, if it does not
  exist, `fallback`. When the method returns, `x[ name ]` has been deleted. ###
  if x[ name ]?
    R = x[ name ]
    delete x[ name ]
  else
    R = fallback
  return R


#===========================================================================================================
# ROUTES
#-----------------------------------------------------------------------------------------------------------
@get_parent_routes = ( route ) ->
  R = []
  #.........................................................................................................
  loop
    R.push route
    break if route.length is 0 or route is '/'
    route = njs_path.dirname route
  #.........................................................................................................
  return R


#===========================================================================================================
# CALLER LOCATION
#-----------------------------------------------------------------------------------------------------------
@get_V8_CallSite_objects = ( delta = 0 ) ->
  ### Save original Error.prepareStackTrace ###
  prepareStackTrace_original = Error.prepareStackTrace
  #.........................................................................................................
  Error.prepareStackTrace = ( ignored, stack ) -> return stack
  error                   = new Error()
  R                       = error.stack
  #.........................................................................................................
  ### Restore original Error.prepareStackTrace ###
  Error.prepareStackTrace = prepareStackTrace_original
  #.........................................................................................................
  delta += 1
  R.splice 0, delta if delta isnt 0
  #.........................................................................................................
  return R

#-----------------------------------------------------------------------------------------------------------
@get_caller_info_stack = ( delta = 0 ) ->
  call_sites = @get_V8_CallSite_objects delta + 1
  R = []
  #.........................................................................................................
  for cs in call_sites
    entry =
      'function-name':    cs.getFunctionName()
      'method-name':      cs.getMethodName()
      'filename':         cs.getFileName()
      'line-nr':          cs.getLineNumber()
      'column-nr':        cs.getColumnNumber()
    R.push entry
  #.........................................................................................................
  return R

#-----------------------------------------------------------------------------------------------------------
@get_caller_routes = ( delta = 0 ) ->
  call_sites = @get_V8_CallSite_objects delta + 1
  return ( cs.getFileName() for cs in call_sites )

#-----------------------------------------------------------------------------------------------------------
@get_filtered_caller_routes = ( delta = 0 ) ->
  call_sites  = @get_V8_CallSite_objects delta + 1
  seen_routes = {}
  R           = []
  #.........................................................................................................
  for cs in call_sites
    route = cs.getFileName()
    ### ignore all duplicate routes: ###
    continue if seen_routes[ route ]?
    seen_routes[ route ] = 1
    ### ignore all 'internal' routes (these typically have no slash, other routes being absolute): ###
    continue if ( route.indexOf '/' ) is -1
    R.push route
  #.........................................................................................................
  return R


#===========================================================================================================
# ID CREATION
#-----------------------------------------------------------------------------------------------------------
@create_id = ( values, length ) ->
  ### Given a number of `values` and a `length`, return an ID with `length` hexadecimal digits (`[0-9a-f]`)
  that deterministically depends on the input but can probably not reverse-engeneered to yield the input
  values. This is in no way meant to be cryptographically strong, just arbitrary enough so that we have a
  convenient method to derive an ID with little chance of overlap given different inputs. **Note** It is
  certainly possible to use this method (or `id_from_text`) to create a hash from a password to be stored in
  a DB. Don't do this. Use `bcrypt` or similar best-practices for password storage. Again, the intent of
  the BITSNPIECES ID utilities is *not* to be 'crypto-safe'; its intent is to give you a tool for generating
  repetition-free IDs. ###
  rpr = ( require 'util' ).inspect
  return @id_from_text ( ( rpr value for value in values ).join '-' ), length

#-----------------------------------------------------------------------------------------------------------
@create_random_id = ( values, length ) ->
  ### Like `create_id`, but with an extra random factor built in that should exclude that two identical
  outputs are ever returned for any two identical inputs. Under the assumption that two calls to this
  method are highly unlikely two produce an identical pair `( 1 * new Date(), Math.random() )` (which could
  only happen if `Math.random()` returned the same number again *within the same clock millisecond*), and
  assuming you are using a reasonable value for `length` (i.e., say, `7 < length < 20`), you should never
  see the same ID twice. ###
  values.push 1 * new Date() * Math.random()
  return @create_id values, length

#-----------------------------------------------------------------------------------------------------------
@get_create_rnd_id = ( seed, delta ) ->
  ### Given an optional `seed` and `delta`, returns a function that will create pseudo-random IDs similar to
  the ones `create_random_id` returns; however, the Bits'n'Pieces `get_rnd` method is used to obtain a
  repeatable random number generator so that ID sequences are repeatable. The underlying PRNG is exposed as
  `fn.rnd`, so `fn.rnd.reset` may be used to start over.

  **Use Case Example**: The below code demonstrates the interesting properties of the method returned by
  `get_create_rnd_id`: **(1)** we can seed the PRNG with numbers of our choice, so we get a chance to create
  IDs that are unlikely to be repeated by other people using the same software, even when later inputs (such
  as the email adresses shown here) happen to be the same. **(2)** Calling the ID generator with three
  diffferent user-specific inputs, we get three different IDs, as expected. **(3)** Repeating the ID
  generation calls with the *same* arguments will yield *different* IDs. **(4)** After calling
  `create_rnd_id.rnd.reset()` and feeding `create_rnd_id` with the *same* user-specific inputs, we can still
  see the identical *same* IDs generated—which is great for testing.

      create_rnd_id = BAP.get_create_rnd_id 1234, 87.23

      # three different user IDs:
      log create_rnd_id [ 'foo@example.com' ], 12
      log create_rnd_id [ 'alice@nosuchname.com' ], 12
      log create_rnd_id [ 'tim@cern.ch' ], 12

      # the same repeated, but yielding random other IDs:
      log()
      log create_rnd_id [ 'foo@example.com' ], 12
      log create_rnd_id [ 'alice@nosuchname.com' ], 12
      log create_rnd_id [ 'tim@cern.ch' ], 12

      # the same repeated, but yielding the same IDs as in the first run:
      log()
      create_rnd_id.rnd.reset()
      log create_rnd_id [ 'foo@example.com' ], 12
      log create_rnd_id [ 'alice@nosuchname.com' ], 12
      log create_rnd_id [ 'tim@cern.ch' ], 12

  The output you should see is

      c40f774fce65
      9d44f31f9a55
      1b26e6e3e736

      a0e11f616685
      d7242f6935c7
      976f26d1b25b

      c40f774fce65
      9d44f31f9a55
      1b26e6e3e736

  Note the last three IDs exactly match the first three IDs. The upshot of this is that we get reasonably
  hard-to-guess, yet on-demand replayable IDs. Apart from weaknesses in the PRNG itself (for which see the
  caveats in the description to `get_rnd`), the obvious way to cheat the system is by making it so that
  a given piece of case-specific data is fed into the ID generator as the n-th call a second time. In
  theory, we could make it so that each call constributes to the state change inside of `create_rnd_id`;
  a replay would then need to provide all of the case-specific pieces of data a second time, in the right
  order. ###
  #.........................................................................................................
  R = ( values, length ) =>
    values.push R.rnd()
    return @create_id values, length
  #.........................................................................................................
  R.rnd = @get_rnd seed, delta
  #.........................................................................................................
  return R

#-----------------------------------------------------------------------------------------------------------
@id_from_text = ( text, length ) ->
  ### Given a `text` and a `length`, return an ID with `length` hexadecimal digits (`[0-9a-f]`)—this is like
  `create_id`, but working on a text rather than a number of arbitrary values. The hash algorithm currently
  used is SHA-1, which returns 40 hex digits; it should be good enough for the task at hand and has the
  advantage of being widely implemented. ###
  ### TAINT should be a user option, or take 'good' algorithm universally available ###
  R = ( ( ( require 'crypto' ).createHash 'sha1' ).update text, 'utf-8' ).digest 'hex'
  return if length? then R[ 0 ... length ] else R



#===========================================================================================================
# APP INFO
#-----------------------------------------------------------------------------------------------------------
@get_app_home = ( routes = null ) ->
  ### Return the file system route to the current (likely) application folder. This works by traversing all
  the routes in `require[ 'main' ][ 'paths' ]` and checking whether one of the `node_modules` folders
  listed there exists and is a folder; the first match is accepted and returned. If no matching existing
  route is found, an error is thrown.

  NB that the algorithm works even if the CoffeeNode Options module has been symlinked from another location
  (rather than 'physically' installed) and even if the application main file has been executed from outside
  the application folder (i.e. this obviates the need to `cd ~/route/to/my/app` before doing `node ./start`
  or whatever—you can simply do `node ~/route/to/my/app/start`), but it does presuppose that (1) there *is*
  a `node_modules` folder in your app folder; (2) there is *no* `node_modules` folder in the subfolder or
  any of the intervening levels (if any) that contains your startup file. Most modules that follow the
  established NodeJS / npm way of structuring modules should naturally comply with these assumptions. ###
  njs_fs = require 'fs'
  routes ?= require[ 'main' ][ 'paths' ]
  #.........................................................................................................
  for route in routes
    try
      return njs_path.dirname route if ( njs_fs.statSync route ).isDirectory()
    #.......................................................................................................
    catch error
      ### silently ignore missing routes: ###
      continue if error[ 'code' ] is 'ENOENT'
      throw error
  #.........................................................................................................
  throw new Error "unable to determine application home; tested routes: \n\n #{routes.join '\n '}\n"


#===========================================================================================================
# WALKING OVER FACETS IN CONTAINERS
#-----------------------------------------------------------------------------------------------------------
@walk_containers_crumbs_and_values = ( value, handler ) ->
  ### Given a `value` and a `handler` with the signature `( error, container, crumbs, value )`, this method
  will call `handler null, container, crumbs, value` for each 'primitive' sub-value ('leaf value') that is
  found inside of `value`, where `container` is the list or POD that contains `value`, and `crumbs` is a
  (possibly empty) list of names that, when transformed as `'/' + crumbs.join '/'`, spells out the locator
  where `value` was found. When `crumbs` is not empty, its last element will be the index (in case of a
  list) or the name (in case of a POD) where `value` was found.

  When iteration is done, the method will make one additional call with all arguments set to `null`;
  consumers are able to detect that iteration has terminated by testing for `crumbs is null`.

  An **example** will show better what's happening:

  ````coffee
  d =
    meaningless: [
      42
      43
      { foo: 1, bar: 2, nested: [ 'a', 'b', ] }
      45 ]
    deep:
      down:
        in:
          a:
            drawer:   'a pen'
            cupboard: 'a pot'
            box:      'a pill'

  BAP.walk_containers_crumbs_and_values d, ( error, container, crumbs, value ) ->
    throw error if error?
    if crumbs is null
      log 'over'
      return
    locator           = '/' + crumbs.join '/'
    # in case you want to mutate values in a container, use:
    [ head..., key, ] = crumbs
    log "#{locator}:", rpr value
  ````

  Output:

  ````
  /meaningless/0: 42
  /meaningless/1: 43
  /meaningless/2/foo: 1
  /meaningless/2/bar: 2
  /meaningless/2/nested/0: 'a'
  /meaningless/2/nested/1: 'b'
  /meaningless/3: 45
  /deep/down/in/a/drawer: 'a pen'
  /deep/down/in/a/cupboard: 'a pot'
  /deep/down/in/a/box: 'a pill'
  over
  ````

  As can be seen, there are no callbacks made for values that are lists or PODs, only for primitive values
  (or objects that are no lists and no PODs). Keep in mind that some JavaScript objects may *look* like PODs
  or lists, but are really something different. As the primary use case for this method is analysis of
  nested configurations read from a JSON file, such complexities have not been considered in the design of
  this method.

  You may pass a single primitive value to `@walk_containers_crumbs_and_values`; this will result in a
  callback where `crumbs` is an empty list and `value` is the value you passed in.

  **Caveats:**

  Because of the way iteration happens in CoffeeScript and JavaScript, it's not a good idea to modify the
  containers you're currently iterating over.
  [MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/for...in#Description)
  has the following to say:

  > If a property is modified in one iteration and then visited at a later time, its value in the loop is
  > its value at that later time. A property that is deleted before it has been visited will not be visited
  > later. Properties added to the object over which iteration is occurring may either be visited or omitted
  > from iteration. **In general it is best not to add, modify or remove properties from the object during
  > iteration, other than the property currently being visited.** There is no guarantee whether or not an
  > added property will be visited, whether a modified property (other than the current one) will be visited
  > before or after it is modified, or whether a deleted property will be visited before it is deleted.

  **Therefore, if deeper modifications are necessary, you may want to do those on a copy of the object
  you're inspecting, or else keep a log of intended changes and execute those changes when iteration has
  stopped.**

  The `crumbs` list in the callback is always the same object, so in case you want to use the values
  elsewhere—and especially when used in an asynchronous fashion—you may want to make a copy of that list.

  The method currently makes no effort to respect bad naming choices in any way, which means that you may
  get faulty or troublesome locators in case names are empty, consist of single or double periods, or
  contain slashes, asterisks or other meta-characters.

  ###
  container = null
  crumbs    = []
  @_walk_containers_crumbs_and_values container, crumbs, value, handler
  return null

#-----------------------------------------------------------------------------------------------------------
@_walk_containers_crumbs_and_values = ( container, crumbs, value, handler ) ->
  ### ( used by @[`walk_containers_crumbs_and_values`](#this.walk_containers_crumbs_and_values)) ###
  TYPES   = require 'coffeenode-types'
  if      TYPES.isa_pod  value then return @_walk_pod_crumbs_and_values  container, crumbs, value, handler
  else if TYPES.isa_list value then return @_walk_list_crumbs_and_values container, crumbs, value, handler
  handler null, container, crumbs, value
  handler null, null, null, null if crumbs.length is 0
  return null

#-----------------------------------------------------------------------------------------------------------
@_walk_list_crumbs_and_values = ( container, crumbs, list, handler ) ->
  ### ( used by @[`walk_containers_crumbs_and_values`](#this.walk_containers_crumbs_and_values)) ###
  for value, idx in list
    crumbs.push idx
    @_walk_containers_crumbs_and_values list, crumbs, value, handler
    crumbs.pop()
  #.........................................................................................................
  handler null, null, null, null if crumbs.length is 0
  return null

#-----------------------------------------------------------------------------------------------------------
@_walk_pod_crumbs_and_values = ( container, crumbs, pod, handler ) ->
  ### ( used by @[`walk_containers_crumbs_and_values`](#this.walk_containers_crumbs_and_values)) ###
  for name, value of pod
    crumbs.push name
    @_walk_containers_crumbs_and_values pod, crumbs, value, handler
    crumbs.pop()
  #.........................................................................................................
  handler null, null, null, null if crumbs.length is 0

#-----------------------------------------------------------------------------------------------------------
@container_and_facet_from_locator = ( container, locator ) ->
  ### The inverse to @[`walk_containers_crumbs_and_values`](#this.walk_containers_crumbs_and_values), this
  method uses a `locator` to drill down into `container`, recursively applying the 'crumbs' (parts) of
  the `locator` until all of the locator has been consumed; it will then return a triplet `[ sub_container,
  key, value, ]`.

  The locator must either be the string `/` (which denotes the `container` itself) or else a string that
  starts with but does not end with a `/`. ###
  rpr = ( require 'util' ).inspect
  if locator is '/'
    return [ null, null, container, ]
  else
    unless /^\/.*?[^\/]$/.test locator
      throw new Error "locator must start with but not end with a slash, got #{rpr locator}"
    ( crumbs = locator.split '/' ).shift()
  return @_container_and_facet_from_crumbs container, locator, crumbs, 0

#-----------------------------------------------------------------------------------------------------------
@container_and_facet_from_crumbs = ( container, crumbs ) ->
  ### Same as @[`container_and_facet_from_locator`](#this.container_and_facet_from_locator), but accepting
  a list of crumbs instead of a locator. ###
  if crumbs is null or crumbs.length is 0
    return [ null, null, container, ]
  locator = '/' + crumbs.join '/'
  return @_container_and_facet_from_crumbs container, locator, crumbs, 0

#-----------------------------------------------------------------------------------------------------------
@_container_and_facet_from_crumbs = ( container, locator, crumbs, idx ) ->
  ### (used by @[`container_and_facet_from_locator`](#this.container_and_facet_from_locator) and
  @[`container_and_facet_from_crumbs`](#this.container_and_facet_from_crumbs))
  ###
  rpr = ( require 'util' ).inspect
  key = crumbs[ idx ]
  throw new Error "unable to get crumb #{idx} from locator #rpr locator" unless key?
  #.........................................................................................................
  try
    value = container[ key ]
  catch error
    value = undefined
  #.........................................................................................................
  if value is undefined
    throw new Error "unable to resolve key #{rpr key} in locator #{rpr locator}"
  #.........................................................................................................
  return [ container, key, value ] if idx == crumbs.length - 1
  return @_container_and_facet_from_crumbs value, locator, crumbs, idx + 1
  return null

#-----------------------------------------------------------------------------------------------------------
@set = ( container, locator_or_crumbs, value ) ->
  TYPES = require 'coffeenode-types'
  if TYPES.isa_list locator_or_crumbs then  method_name = 'container_and_facet_from_crumbs'
  else                                      method_name = 'container_and_facet_from_locator'
  [ container
    key
    old_value ]     = @[ method_name ] container, locator_or_crumbs
  container[ key ]  = value
  return [ container, key, old_value, ]


