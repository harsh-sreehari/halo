; PHP Laravel Route & Handler SCM queries for HALO

; Laravel Route static calls: Route::get(...), Route::post(...)
(scoped_call_expression
  scope: (name) @scope
  name: (name) @method
  arguments: (arguments
    . (argument) @path
    . (argument)? @handler)
) @route

; Standalone function definitions
(function_definition
  name: (name) @fn_name
  parameters: (formal_parameters) @fn_params
  body: (compound_statement) @fn_body) @function

; Class method declarations
(method_declaration
  name: (name) @fn_name
  parameters: (formal_parameters) @fn_params
  body: (compound_statement) @fn_body) @method

; Class declarations
(class_declaration
  name: (name) @class_name
  body: (declaration_list) @class_body) @class
