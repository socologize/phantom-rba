def regex_extract_powershell_b64_and_decode(input_string=None, **kwargs):
    """
    Attempts to extract base64 encoded powershell and convert to text
    
    Args:
        input_string (CEF type: *): A powershell cmdline that contains encoding flag
    
    Returns a JSON-serializable object that implements the configured data paths:
        decoded_string (CEF type: *): Base 64 extracted from input_string and decoded to plain text
        extracted_string: Base 64 String extracted from input_string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    from base64 import b64decode
    outputs = {}

    if input_string:
        if re.search('\-[eE^]{1,2}[NnCcOoDdEeMmAa^]+\s+([^\s]+)',input_string):
            captured_string = re.search('\-[eE^]{1,2}[NnCcOoDdEeMmAa^]+\s+([^\s]+)',input_string).group(1)
            if captured_string.endswith('=='):
                phantom.debug('captured string')
            elif captured_string.endswith('='):
                phantom.debug('captured string - padding string with "="')
                captured_string += '='
            else:
                phantom.debug('captured string - padding string with "=="')
                captured_string += '=='
            outputs['extracted_string'] = captured_string
            decoded_string = b64decode(captured_string).replace('\x00','')
            outputs['decoded_string'] = decoded_string
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
