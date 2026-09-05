; Python Route & Handler SCM queries for HALO

; FastAPI & Flask route decorators on function definitions
(decorated_definition
  (decorator
    (call
      function: (attribute
        object: (_) @router
        attribute: (identifier) @method)
      arguments: (argument_list) @decorator_args)
  ) @decorator
  definition: (function_definition
    name: (identifier) @handler_name
    parameters: (parameters) @params) @definition
) @route

; Function definitions (sync and async)
(function_definition
  name: (identifier) @fn_name
  parameters: (parameters) @fn_params
  body: (block) @fn_body) @function

; Class definitions
(class_definition
  name: (identifier) @class_name
  body: (block) @class_body) @class
