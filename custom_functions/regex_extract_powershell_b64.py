def regex_extract_powershell_b64(input_string=None, **kwargs):
    """
    Detects -enc flag and extracts base64. Based on Unit42 research.
    
    Args:
        input_string (CEF type: *): A powershell cmdline that may contain encoding flag
    
    Returns a JSON-serializable object that implements the configured data paths:
        extracted_string (CEF type: *): Base 64 extracted from input_string. Empty if extraction failed.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    from base64 import b64decode
    outputs = {}
    pattern = '\-[eE^]{1,2}[NnCcOoDdEeMmAa^]+\s+([^\s]+)'
    if input_string:
        if re.search(pattern,str(input_string)):
            captured_string = re.search(pattern,str(input_string)).group(1)
            outputs['extracted_string'] = captured_string
        else:
            phantom.debug("No base64 encoding detected")
            
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
