

############################################################################################################
njs_path                  = require 'path'




#-----------------------------------------------------------------------------------------------------------
@equals = ( a, b ) ->
  assert = require 'assert'
  try
    assert.deepEqual a, b
    return true
  catch error
    return false

#-----------------------------------------------------------------------------------------------------------
@format_number = ( n ) ->
  n       = n.toString()
  f       = ( n ) -> return h n, /(\d+)(\d{3})/
  h       = ( n, re ) -> n = n.replace re, "$1" + "'" + "$2" while re.test n; return n
  return f n

#-----------------------------------------------------------------------------------------------------------
@escape_regex = ( text ) ->
  ### Given a `text`, return the same with all regular expression metacharacters properly escaped. Escaped
  characters are `[]{}()*+?-.,\^$|#` plus whitespace.###
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
  ###

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
@create_repeatable_random_id = ( values, length ) ->
  ### Like `create_random_id`, but with an extra random factor built in that should exclude that two identical
  outputs are ever returned for any two identical inputs. Under the assumption that two calls to this
  method are highly unlikely two produce an identical pair `( 1 * new Date(), Math.random() )` (which could
  only happen if `Math.random()` returned the same number again *within the same clock millisecond*), and
  assuming you are using a reasonable value for `length` (i.e., say, `7 < length < 20`), you should never
  see the same ID twice. ###
  values.push @rn
  return @create_id values, length

#-----------------------------------------------------------------------------------------------------------
@id_from_text = ( text, length ) ->
  ### Given a `text` and a `length`, return an ID with `length` hexadecimal digits (`[0-9a-f]`)—this is like
  `create_id`, but working on a text rather than a number of arbitrary values. The hash algorithm currently
  used is SHA-1, which returns 40 hex digits; it should be good enough for the task at hand and has the
  advantage of being widely implemented. ###
  ### TAINT should be a user option, or take 'good' algorithm universally available ###
  R = ( ( ( require 'crypto' ).createHash 'sha1' ).update text, 'utf-8' ).digest 'hex'
  return if length? then R[ 0 ... length ] else R






