def normalize_lists(var=None, object_type=None, **kwargs):
    """
    Takes in an object that may be a single element or a list and normalizes the output. Data can be accessed by items.*.<object_type>. Object_type defaults to 'object_type'
    
    Args:
        var
        object_type
    
    Returns a JSON-serializable object that implements the configured data paths:
        items
        items.*.object_type
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {'items': []}
    
    if not object_type:
        object_type = 'object_type'
    # Write your custom code here...
    if var and type(var) == list and object_type:
        for item in var:
            outputs['items'].append({object_type: item})
    elif var and object_type:
        outputs['items'].append({object_type: var})
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
