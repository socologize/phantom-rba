def decode_base64(input_string=None, **kwargs):
    """
    Decodes provided base64 string
    
    Args:
        input_string (CEF type: *): Base64 encoded text
    
    Returns a JSON-serializable object that implements the configured data paths:
        decoded_string (CEF type: *): Base64 decoded string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    from base64 import b64decode
    outputs = {}

    if input_string:
        if input_string.endswith('=='):
            phantom.debug('padding exists')
        elif input_string.endswith('='):
            phantom.debug('padding string with "="')
            input_string += '='
        else:
            phantom.debug('padding string with "=="')
            input_string += '=='
            
        decoded_string = b64decode(input_string).replace('\x00','')
        outputs['decoded_string'] = decoded_string
            
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
