"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

from dateutil.parser import parse
from django.utils.dateparse import parse_datetime
import re
import random

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

def format_splunk_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('format_splunk_query() called')
    
    template = """index=risk risk_object=\"{0}\"
| where (_time >={1}+21600 AND _time<={2}+21600)
|  eval source=replace(source,\"\\w+\\s+-\\s+\\w+\\s+-\\s+([^-]+)\\s+-.*\",\"\\1\")
| stats earliest(_time) as _time values(*) as * by source | fields - user_* src_user_* src_* dest_* dest_user_* info_* search_* splunk_* tag* risk_modifier* risk_rule* sourcetype timestamp index next_cron_time"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.risk_object",
        "filtered-data:filter_1:condition_1:artifact:*.cef.info_min_time",
        "filtered-data:filter_1:condition_1:artifact:*.cef.info_max_time",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_splunk_query")

    fetch_risk_rules(container=container)

    return

def fetch_risk_rules(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('fetch_risk_rules() called')

    # collect data for 'fetch_risk_rules' call
    formatted_data_1 = phantom.get_format_data(name='format_splunk_query')

    parameters = []
    
    # build parameters list for 'fetch_risk_rules' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['es_rba'], callback=parse_risk_rules, name="fetch_risk_rules")

    return

def parse_risk_rules(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('parse_risk_rules() called')
    results_data_1 = phantom.collect2(container=container, datapath=['fetch_risk_rules:action_result.data'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    parse_risk_rules__json_dict = None
    parse_risk_rules__threat_object_dict = None
    parse_risk_rules__threat_object_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

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

    parse_risk_rules__json_dict = []
    parse_risk_rules__threat_object_dict = []
    threatlist = []
    parameters = []
    cef_data = []
    
    for search_json in results_item_1_0[0]:
        field_mapping = {}
        tags = []
        # perform cif_cef translation
        for k,v in search_json.items():
            if k in cim_cef.keys():
                search_json[cim_cef[k]] = search_json.pop(k)       
        if 'risk_message' in search_json.keys():
            search_json['description'] = search_json.pop('risk_message')
            
        # make _time easier to read
        if '_time' in search_json.keys():
            timestring = parse(search_json['_time'])
            search_json['_time'] = "{} {}".format(timestring.date(), timestring.time())
        
        # parse through threat_objects
        if 'threat_object' in search_json.keys():
            if search_json['threat_object_type'] == 'process' and 'cmdline' in search_json.keys():
                search_json['threat_object'] = search_json['cmdline']
                search_json['threat_object_type'] = 'command'
                
            if type(search_json['threat_object']) == list:
                for listitem in search_json['threat_object']:
                    threatlist.append(listitem)
            else:
                threatlist.append(search_json['threat_object'])
            
            parse_risk_rules__threat_object_dict.append(
                {'_time': search_json['_time'],
                 'original_risk_rule': search_json['source'],               
                 'threat_object': search_json['threat_object'], 
                 'threat_object_type': search_json['threat_object_type']})
            
        # extract tags
        if 'rule_attack_tactic_technique' in search_json.keys():
                for match in re.findall('(^|\|)(\w+)\s+',search_json['rule_attack_tactic_technique']):
                    tags.append(match[1])
                search_json['tactic'] = tags
                    
        parse_risk_rules__json_dict.append(search_json)
    parse_risk_rules__threat_object_count = len(set(threatlist))
    parse_risk_rules__threat_object_dict = sorted(parse_risk_rules__threat_object_dict, key=lambda i: i['_time'])
    phantom.debug("Final JSON dict: {}".format(parse_risk_rules__json_dict))
    phantom.debug("Final threat_object dict: {}".format(parse_risk_rules__threat_object_dict))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='parse_risk_rules:json_dict', value=json.dumps(parse_risk_rules__json_dict))
    phantom.save_run_data(key='parse_risk_rules:threat_object_dict', value=json.dumps(parse_risk_rules__threat_object_dict))
    phantom.save_run_data(key='parse_risk_rules:threat_object_count', value=json.dumps(parse_risk_rules__threat_object_count))
    add_risk_rule_artifact(container=container)
    decision_4(container=container)

    return

def pin_risk_object(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('pin_risk_object() called')

    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.risk_object'])

    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    phantom.pin(container=container, data=filtered_artifacts_item_1_0, message="Risk Object", pin_type="card", pin_style="blue", name=None)
    pin_risk_score(container=container)

    return

def pin_risk_score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('pin_risk_score() called')

    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.risk_ScoreSum'])

    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    phantom.pin(container=container, data=filtered_artifacts_item_1_0, message="Total Risk Score", pin_type="card", pin_style="blue", name=None)

    return

def set_container_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('set_container_low() called')

    phantom.set_severity(container=container, severity="Low")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.risk_ScoreSum", "<", 200],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        update_artifact_sev_low(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef. risk_ScoreSum", ">=", 200],
            ["artifact:*.cef.risk_ScoreSum", "<", 250],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        update_artifact_sev_med(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.risk_ScoreSum", ">=", 250],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        update_artifact_sev_high(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def set_container_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('set_container_high() called')

    phantom.set_severity(container=container, severity="High")

    return

def set_container_med(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('set_container_med() called')

    phantom.set_severity(container=container, severity="Medium")

    return

def playbook_undefined_local_RBA_Investigate_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('playbook_undefined_local_RBA_Investigate_1() called')
    
    # call playbook "local/RBA Investigate", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/RBA Investigate", container=container)

    return

def update_artifact_sev_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('update_artifact_sev_high() called')

    # collect data for 'update_artifact_sev_high' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'update_artifact_sev_high' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'data': "{\"label\":\"splunk\",\"severity\":\"high\"}",
                'overwrite': True,
                'artifact_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact fields", parameters=parameters, assets=['phantom_helper'], callback=set_container_high, name="update_artifact_sev_high")

    return

def update_artifact_sev_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('update_artifact_sev_low() called')

    # collect data for 'update_artifact_sev_low' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'update_artifact_sev_low' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'data': "{\"label\":\"splunk\",\"severity\":\"low\"}",
                'overwrite': True,
                'artifact_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact fields", parameters=parameters, assets=['phantom_helper'], callback=set_container_low, name="update_artifact_sev_low")

    return

def update_artifact_sev_med(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('update_artifact_sev_med() called')

    # collect data for 'update_artifact_sev_med' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'update_artifact_sev_med' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'data': "{\"label\":\"splunk\",\"severity\":\"medium\"}",
                'overwrite': True,
                'artifact_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="update artifact fields", parameters=parameters, assets=['phantom_helper'], callback=set_container_med, name="update_artifact_sev_med")

    return

def pin_total_detections(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('pin_total_detections() called')

    results_data_1 = phantom.collect2(container=container, datapath=['fetch_risk_rules:action_result.summary.total_events'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.pin(container=container, data=results_item_1_0, message="Total Risk Detections", pin_type="card", pin_style="red", name=None)
    pin_total_threats(container=container)

    return

def format_splunk_asset_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('format_splunk_asset_query() called')
    
    template = """index=placeholder earliest=-1s latest=now 
| inputlookup append=t asset_lookup_by_str where IN ({0})"""

    # parameter list for template variable replacement
    parameters = [
        "fetch_risk_rules:action_result.data.*.risk_object",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_splunk_asset_query")

    fetch_asset_enrichment(container=container)

    return

def fetch_identity_enrichment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('fetch_identity_enrichment() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'fetch_identity_enrichment' call
    formatted_data_1 = phantom.get_format_data(name='format_splunk_identity_query')

    parameters = []
    
    # build parameters list for 'fetch_identity_enrichment' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['es_rba'], callback=join_add_risk_object_artifact, name="fetch_identity_enrichment")

    return

def format_splunk_identity_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('format_splunk_identity_query() called')
    
    template = """index=placeholder earliest=-1s latest=now 
| inputlookup append=t identity_lookup_expanded where identity IN ({0})"""

    # parameter list for template variable replacement
    parameters = [
        "fetch_risk_rules:action_result.data.*.risk_object",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_splunk_identity_query")

    fetch_identity_enrichment(container=container)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["fetch_risk_rules:action_result.data.*.risk_object_type", "==", "system"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_splunk_asset_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["fetch_risk_rules:action_result.data.*.risk_object_type", "==", "user"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        format_splunk_identity_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def fetch_asset_enrichment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('fetch_asset_enrichment() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'fetch_asset_enrichment' call
    formatted_data_1 = phantom.get_format_data(name='format_splunk_asset_query')

    parameters = []
    
    # build parameters list for 'fetch_asset_enrichment' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['es_rba'], callback=join_add_risk_object_artifact, name="fetch_asset_enrichment")

    return

def add_risk_object_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('add_risk_object_artifact() called')
    results_data_1 = phantom.collect2(container=container, datapath=['fetch_asset_enrichment:action_result.data.'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['fetch_identity_enrichment:action_result.data.'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.risk_object'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    cef_data = {}
    if results_item_1_0:
        # phantom.debug('Asset Info: {}'.format(results_item_1_0[0][0]))
        for k,v in results_item_1_0[0][0].items():
            if not k.startswith("_"):
                cef_data[k] = v
        cef_data['risk_object'] = filtered_artifacts_item_1_0[0]
        success, message, artifact_id = phantom.add_artifact(container=container['id'], raw_data={}, cef_data=cef_data, label="risk_object", name="Risk Object Information", severity="informational", identifier=None, trace=False, run_automation=False)
    if results_item_2_0:
        for k,v in results_item_2_0[0][0].items():
            if not k.startswith("_"):
                cef_data[k] = v
        # phantom.debug('Identity Info: {}'.format(results_item_2_0[0][0]))
        cef_data['risk_object'] = filtered_artifacts_item_1_0[0]
        success, message, artifact_id = phantom.add_artifact(container=container['id'], raw_data={}, cef_data=cef_data, label="risk_object", name="Risk Object Information", severity="informational", identifier=None, trace=False, run_automation=False)
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def join_add_risk_object_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_add_risk_object_artifact() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_add_risk_object_artifact_called'):
        return

    # no callbacks to check, call connected block "add_risk_object_artifact"
    phantom.save_run_data(key='join_add_risk_object_artifact_called', value='add_risk_object_artifact', auto=True)

    add_risk_object_artifact(container=container, handle=handle)
    
    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.label", "==", "artifact"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_splunk_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        pin_risk_object(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        decision_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.label", "==", "risk_rule"],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        playbook_undefined_local_RBA_Investigate_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def add_risk_rule_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('add_risk_rule_artifact() called')
    parse_risk_rules__json_dict = json.loads(phantom.get_run_data(key='parse_risk_rules:json_dict'))

    add_risk_rule_artifact__tags = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    add_risk_rule_artifact__tags = []
    tags = []
    for artifact_json in parse_risk_rules__json_dict:
        name = artifact_json.pop('source')
        if 'tactic' in artifact_json.keys():
            tags.append(artifact_json.pop('tactic'))
        success, message, artifact_id = phantom.add_artifact(
            container=container['id'], raw_data={}, 
            cef_data=artifact_json, 
            label="risk_rule", 
            name=name, 
            severity="informational")
        
        artifact_json['artifact_id'] = artifact_id
        add_risk_rule_artifact__tags.append({'artifact_id': artifact_id, 'tags': tags})

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='add_risk_rule_artifact:tags', value=json.dumps(add_risk_rule_artifact__tags))
    pin_total_detections(container=container)

    return

def pin_total_threats(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('pin_total_threats() called')

    parse_risk_rules__threat_object_count = json.loads(phantom.get_run_data(key='parse_risk_rules:threat_object_count'))

    phantom.pin(container=container, data=parse_risk_rules__threat_object_count, message="Total Unique Threats", pin_type="card", pin_style="blue", name=None)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return