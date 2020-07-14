def vault_filter_filetype_allowlist(filetype=None, filetype_allowlist=None, vault_id=None, **kwargs):
    """
    Input a list of file content types, vault ids and the name of a custom_list that contains safe file types. Output vauld ids where the filetype is NOT present in the custom_list. 
    
    Args:
        filetype (CEF type: *): Supports Content-Type from Vault Artifact
        filetype_allowlist (CEF type: *): The name of a custom list that will be used as the list of domains to filter the URL against. Only the first column of the custom list will be used. Example: https://web.example.com/ will be parsed as web.example.com and matched to values inside my_custom_list.
        vault_id (CEF type: vault id): Vault ID
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.filtered_vault_id (CEF type: vault id): Only vault_id's where the content-type is not found within the custom list
        *.filtered_content_type
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import urlparse
    
    outputs = []
    custom_list = phantom.get_list(list_name=filetype_allowlist)[2]
    custom_list = [item[0] for item in custom_list]
    for file,vault in zip(filetype, vault_id):
        if file and vault:
            extracted_filetype = file.split(';')[0]
            if extracted_filetype not in custom_list:
                outputs.append({'filtered_vault_id': vault, 'filtered_content_type': extracted_filetype})
                
    phantom.debug("Filtered Vault Items: {}".format(outputs))
        
    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
