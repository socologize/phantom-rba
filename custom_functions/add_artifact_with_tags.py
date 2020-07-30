def add_artifact_with_tags(cef=None, tags=None, severity=None, container_id=None, label=None, name=None, **kwargs):
    """
    Adds an artifact and updates that artifact with provided tags
    
    Args:
        cef (CEF type: *)
        tags (CEF type: *)
        severity (CEF type: *)
        container_id (CEF type: phantom container id)
        label (CEF type: *)
        name (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        id
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    success, message, artifact_id = phantom.add_artifact(
            container=container_id, raw_data={}, 
            cef_data=cef, 
            label=label,
            field_mapping=None,
            name=name, 
            severity=severity)
    
    artifact_url = phantom.build_phantom_rest_url('artifact', artifact_id)
    data = {'tags': tags}
    phantom.requests.post(artifact_url, data=json.dumps(data), verify=False)
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
