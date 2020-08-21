"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_rba_master_regex_extract_powershell_b64_1' block
    cf_rba_master_regex_extract_powershell_b64_1(container=container)

    return

def cf_community_regex_extract_ipv4_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_regex_extract_ipv4_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_rba_master_decode_base64_1:custom_function_result.data.decoded_string'], action_results=results )

    parameters = []

    custom_function_result_0_0 = [item[0] for item in custom_function_result_0]

    parameters.append({
        'input_string': custom_function_result_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/regex_extract_ipv4", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/regex_extract_ipv4', parameters=parameters, name='cf_community_regex_extract_ipv4_1', callback=subnet_filter)

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_1' call
    filtered_custom_function_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:subnet_filter:condition_1:cf_community_regex_extract_ipv4_1:custom_function_result.data.*.ipv4'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for filtered_custom_function_results_item_1 in filtered_custom_function_results_data_1:
        if filtered_custom_function_results_item_1[0]:
            parameters.append({
                'ip': filtered_custom_function_results_item_1[0],
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], name="ip_reputation_1")

    return

def subnet_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('subnet_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_community_regex_extract_ipv4_1:custom_function_result.data.*.ipv4", "not in", "10.0.0.0/8"],
            ["cf_community_regex_extract_ipv4_1:custom_function_result.data.*.ipv4", "not in", "172.16.0.0/12"],
            ["cf_community_regex_extract_ipv4_1:custom_function_result.data.*.ipv4", "not in", "192.168.0.0/16"],
        ],
        logical_operator='and',
        name="subnet_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def cf_rba_master_regex_extract_powershell_b64_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_rba_master_regex_extract_powershell_b64_1() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.threat_object', 'artifact:*.id'])

    parameters = []

    for item0 in container_data_0:
        parameters.append({
            'artifact_id': item0[1],
            'input_string': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "rba-master/regex_extract_powershell_b64", returns the custom_function_run_id
    phantom.custom_function(custom_function='rba-master/regex_extract_powershell_b64', parameters=parameters, name='cf_rba_master_regex_extract_powershell_b64_1', callback=decision_1)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_rba_master_regex_extract_powershell_b64_1:custom_function_result.data.extracted_string", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_1() called')

    formatted_data_1 = phantom.get_format_data(name='format_3')

    phantom.pin(container=container, data=formatted_data_1, message="Possible Encoded Powershell", pin_type="card", pin_style="red", name=None)

    return

def cf_rba_master_decode_base64_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_rba_master_decode_base64_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_rba_master_regex_extract_powershell_b64_1:custom_function_result.data.artifact_id', 'cf_rba_master_regex_extract_powershell_b64_1:custom_function_result.data.extracted_string'], action_results=results )

    parameters = []

    for item0 in custom_function_result_0:
        parameters.append({
            'artifact_id': item0[0],
            'input_string': item0[1],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "rba-master/decode_base64", returns the custom_function_run_id
    phantom.custom_function(custom_function='rba-master/decode_base64', parameters=parameters, name='cf_rba_master_decode_base64_1', callback=cf_rba_master_decode_base64_1_callback)

    return

def cf_rba_master_decode_base64_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('cf_rba_master_decode_base64_1_callback() called')
    
    cf_community_regex_extract_ipv4_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_rba_master_decode_base64_1:custom_function_result.data.decoded_string", "!=", ""],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_rba_master_json_serializer_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def cf_rba_master_json_serializer_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_rba_master_json_serializer_1() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:cf_rba_master_decode_base64_1:custom_function_result.data.decoded_string'])
    literal_values_0 = [
        [
            "decodedString",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in filtered_custom_function_results_data_0:
            parameters.append({
                'input_key': item0[0],
                'input_value': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "rba-master/json_serializer", returns the custom_function_run_id
    phantom.custom_function(custom_function='rba-master/json_serializer', parameters=parameters, name='cf_rba_master_json_serializer_1', callback=format_2)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """{{\"cef\": {0}}}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_rba_master_json_serializer_1:custom_function_result.data.json",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    cf_rba_master_update_artifact_1(container=container)

    return

def cf_rba_master_update_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_rba_master_update_artifact_1() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:cf_rba_master_decode_base64_1:custom_function_result.data.artifact_id'])
    formatted_data_0 = [
        [
            phantom.get_format_data(name="format_2"),
        ],
    ]

    parameters = []

    for item0 in filtered_custom_function_results_data_0:
        for item1 in formatted_data_0:
            parameters.append({
                'artifact_id': item0[0],
                'data': item1[0],
                'overwrite': None,
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "rba-master/update_artifact", returns the custom_function_run_id
    phantom.custom_function(custom_function='rba-master/update_artifact', parameters=parameters, name='cf_rba_master_update_artifact_1')

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_3() called')
    
    template = """Artifact {0} has possible encoded powershell"""

    # parameter list for template variable replacement
    parameters = [
        "cf_rba_master_regex_extract_powershell_b64_1:custom_function_result.data.artifact_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    pin_1(container=container)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["cf_rba_master_regex_extract_powershell_b64_1:custom_function_result.data.extracted_string", "!=", ""],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_community_noop_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def cf_community_noop_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_noop_1() called')
    
    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/noop", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/noop', parameters=parameters, name='cf_community_noop_1')

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