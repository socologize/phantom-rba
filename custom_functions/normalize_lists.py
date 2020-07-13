def normalize_lists(input_item=None, object_type=None, **kwargs):
    """
    Takes in an object that may be a single element or a list and normalizes the output. Data can be accessed by items.*.<object_type>. Object_type defaults to 'object_type'
    
    Args:
        input_item
        object_type
    
    Returns a JSON-serializable object that implements the configured data paths:
        item
        object_type
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}

    if input_item and type(input_item) == list and object_type:
        for item in input_item:
            outputs['item'] = 'item'
            outputs['object_type'] = object_type
    elif input_item and object_type:
        outputs['item'] = input_item
        outputs['object_type'] = object_type
    
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
