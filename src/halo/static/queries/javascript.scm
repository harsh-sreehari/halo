; JavaScript & TypeScript Route & Handler SCM queries for HALO

; Express route calls: app.get(...), router.post(...)
(call_expression
  function: (member_expression
    object: (_) @router
    property: (property_identifier) @method)
  arguments: (arguments
    . (string) @path) @args
) @route

; Function declarations
(function_declaration
  name: (identifier) @fn_name
  parameters: (formal_parameters) @fn_params
  body: (statement_block) @fn_body) @function

; Arrow functions assigned to variables: const handler = (req, res) => { ... }
(variable_declarator
  name: (identifier) @fn_name
  value: (arrow_function
    parameters: (formal_parameters) @fn_params
    body: (_) @fn_body)) @arrow_function

; Function expressions assigned to variables: const handler = function(req, res) { ... }
(variable_declarator
  name: (identifier) @fn_name
  value: (function
    parameters: (formal_parameters) @fn_params
    body: (statement_block) @fn_body)) @function_expr

; Class method definitions
(method_definition
  name: (property_identifier) @fn_name
  parameters: (formal_parameters) @fn_params
  body: (statement_block) @fn_body) @method

; Class declarations
(class_declaration
  name: (identifier) @class_name
  body: (class_body) @class_body) @class
