def regex_findall(input_string=None, input_pattern=None, **kwargs):
    """
    Custom function implementation of re.find_all. Takes an input_string and a regex_pattern and returns matches (up to 9).
    
    Args:
        input_string (CEF type: *): A string to run regex against
        input_pattern (CEF type: *): Regex pattern goes here
    
    Returns a JSON-serializable object that implements the configured data paths:
        all (CEF type: *): Entire result of re.findall
        group1 (CEF type: *)
        group2 (CEF type: *)
        group3 (CEF type: *)
        group4 (CEF type: *)
        group5 (CEF type: *)
        group6 (CEF type: *)
        group7 (CEF type: *)
        group8 (CEF type: *)
        group9 (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = {}
    
    pattern = '{}'.format(input_pattern)
    
    result = re.findall(pattern, input_string)
    
    phantom.debug('Number of capture groups: {}'.format(len(result)))
    if len(result) > 9:
        phantom.debug('Number of capture groups greater than allowable output size of 9. Returning first 9')
        outputs['all'] = result[:9]
        incrementer = 1
        for capture_group in result[:9]:
            outputs['group' + str(incrementer)] = capture_group
            incrementer += 1
    elif result:
        outputs['all'] = result
        incrementer = 1
        for capture_group in result:
            outputs['group' + str(incrementer)] = capture_group
            incrementer += 1
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs