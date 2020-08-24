def parse_risk_results(search_json=None, **kwargs):
    """
    Args:
        search_json (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.artifact.cef (CEF type: *)
        *.artifact.tags (CEF type: *)
        *.artifact.name
        *.artifact.field_mapping (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from dateutil.parser import parse
    from django.utils.dateparse import parse_datetime
    import re
    
    outputs = []
    cim_cef = {
        "action": "act", 
        "action_name": "act", 
        "app": "app", 
        "bytes_in": "bytesIn", 
        "bytes_out": "bytesOut", 
        "category": "cat", 
        "dest": "destinationAddress", 
        "dest_ip": "destinationAddress", 
        "dest_mac": "destinationMacAddress", 
        "dest_nt_domain": "destinationNtDomain", 
        "dest_port": "destinationPort", 
        "dest_translated_ip": "destinationTranslatedAddress", 
        "dest_translated_port": "destinationTranslatedPort", 
        "direction": "deviceDirection",
        "dns": "destinationDnsDomain", 
        "dvc": "dvc", 
        "dvc_ip": "deviceAddress", 
        "dvc_mac": "deviceMacAddress", 
        "file_create_time": "fileCreateTime", 
        "file_hash": "fileHash", 
        "file_modify_time": "fileModificationTime", 
        "file_name": "fileName", 
        "file_path": "filePath", 
        "file_size": "fileSize", 
        "message": "message", 
        "protocol": "transportProtocol", 
        "request_payload": "request", 
        "request_payload_type": "requestMethod", 
        "src": "sourceAddress", 
        "src_dns": "sourceDnsDomain", 
        "src_ip": "sourceAddress", 
        "src_mac": "sourceMacAddress", 
        "src_nt_domain": "sourceNtDomain", 
        "src_port": "sourcePort", 
        "src_translated_ip": "sourceTranslatedAddress", 
        "src_translated_port": "sourceTranslatedPort", 
        "src_user": "sourceUserId", 
        "transport": "transportProtocol", 
        "url": "requestURL", 
        "user": "destinationUserName", 
        "user_id": "destinationUserId", 
    }
    field_mapping = {}
    
    for artifact_json in search_json[0]:
        for k,v in artifact_json.items():
            tags = []
            # Swap CIM for CEF values
            if k in cim_cef.keys():
                artifact_json[cim_cef[k]] = artifact_json.pop(k)

        # Swap risk_message for description
        if 'risk_message' in artifact_json.keys():
            artifact_json['description'] = artifact_json.pop('risk_message')

        # Make _time easier to read
        if '_time' in artifact_json.keys():
            timestring = parse(artifact_json['_time'])
            artifact_json['_time'] = "{} {}".format(timestring.date(), timestring.time())

        # extract tags
        if 'rule_attack_tactic_technique' in artifact_json.keys():
            for match in re.findall('(^|\|)(\w+)\s+',artifact_json['rule_attack_tactic_technique']):
                tags.append(match[1])

        # Run json.dumps against threat_objects if causing automation issues down the line
        # if 'threat_object' in artifact_json.keys():
        #    artifact_json['threat_object'] = json.dumps(artifact_json['threat_object'])[1:-1]
        
        # Add threat_object_type to threat_object field_mapping:
        if 'threat_object' in artifact_json.keys() and 'threat_object' in artifact_json.keys():
            field_mapping['threat_object'] = artifact_json['threat_object_type']
            
        # Extract tags
        if 'rule_attack_tactic_technique' in artifact_json.keys():
            for match in re.findall('(^|\|)(\w+)\s+',artifact_json['rule_attack_tactic_technique']):
                tags.append(match[1])
            tags=list(set(tags))

        # build output - source must exist
        if 'source' in artifact_json.keys():
            name = artifact_json.pop('source')
            outputs.append({'artifact': {'cef': artifact_json, 'tags': tags, 'name': name, 'field_mapping': field_mapping}})


    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
