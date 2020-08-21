"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import urlparse
import datetime

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_5' block
    decision_5(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.automation_flag", "==", True],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = container['owner']
    message = """The following items were identified as malicious. Please review the evidence and decide which items you would like to take action on (Yes/No)."""
    threat_object = [item[0] for item in phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.threat_object'])]
    threat_object_type = [item[0] for item in phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.threat_object_type'])]

    # dynamic response builder
    response_types = []
    pairings = []
    for thr_obj,thr_obj_type in zip(threat_object,threat_object_type):
          if thr_obj:
                response_types.append({
                    "prompt": "Block {}".format(thr_obj),
                    "options": {
                        "type": "list",
                        "choices": [
                            "Yes",
                            "No",
                        ]
                    },
                })
                pairings.append({thr_obj_type: thr_obj})
    
    phantom.save_run_data(value=json.dumps(pairings), key='pairings', auto=True)

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", response_types=response_types, callback=get_run_data)

    return

def get_run_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_run_data() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['prompt_1:action_result.summary.responses'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    get_run_data__output = None
    get_run_data__responses = None
    get_run_data__now = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    get_run_data__output = phantom.get_run_data(key='pairings')
    get_run_data__responses = results_item_1_0
    get_run_data__now = str(datetime.datetime.now())
    ################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='get_run_data:output', value=json.dumps(get_run_data__output))
    phantom.save_run_data(key='get_run_data:responses', value=json.dumps(get_run_data__responses))
    phantom.save_run_data(key='get_run_data:now', value=json.dumps(get_run_data__now))
    cf_rba_master_dynamic_prompt_pairing_1(container=container)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.automation_flag", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def trace_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('trace_email_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'trace_email_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_community_datetime_modify_2:custom_function_result.data.datetime_string'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_community_datetime_modify_1:custom_function_result.data.datetime_string'], action_results=results)
    filtered_custom_function_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_4:condition_3:cf_local_dynamic_prompt_pairing_1:custom_function_result.data.value'])

    parameters = []
    
    # build parameters list for 'trace_email_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            for filtered_custom_function_results_item_1 in filtered_custom_function_results_data_1:
                parameters.append({
                    'ToIP': "",
                    'FromIP': "",
                    'EndDate': custom_function_results_item_1[0],
                    'MessageId': "",
                    'StartDate': custom_function_results_item_2[0],
                    'WidgetFilter': False,
                    'SenderAddress': filtered_custom_function_results_item_1[0],
                    'RecipientAddress': "",
                })

    phantom.act(action="trace email", parameters=parameters, assets=['message_trace'], callback=decision_4, name="trace_email_1")

    return

def join_trace_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_trace_email_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['cf_community_datetime_modify_1', 'cf_community_datetime_modify_2']):
        
        # call connected block "trace_email_1"
        trace_email_1(container=container, handle=handle)
    
    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["trace_email_1:action_result.summary.emails_found", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["trace_email_1:action_result.data.*.*.RecipientAddress", "!=", ""],
            ["trace_email_1:action_result.data.*.*.MessageId", "!=", ""],
        ],
        logical_operator='and',
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        run_query_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def cf_community_datetime_modify_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_datetime_modify_1() called')
    
    container_property_0 = [
        [
            container.get("create_time"),
        ],
    ]
    literal_values_0 = [
        [
            -7,
            "days",
            "%Y-%m-%d %H:%M:%S.%f+00",
            "%Y-%m-%dT%H:%M:%SZ",
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        for item1 in literal_values_0:
            parameters.append({
                'input_datetime': item0[0],
                'amount_to_modify': item1[0],
                'modification_unit': item1[1],
                'input_format_string': item1[2],
                'output_format_string': item1[3],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='cf_community_datetime_modify_1', callback=join_trace_email_1)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.type", "==", "url"],
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.response", "==", "Yes"],
        ],
        logical_operator='and',
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_local_regex_findall_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.type", "==", "domain"],
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.response", "==", "Yes"],
        ],
        logical_operator='and',
        name="filter_4:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.type", "==", "sender"],
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.response", "==", "Yes"],
        ],
        logical_operator='and',
        name="filter_4:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        cf_community_datetime_modify_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)
        cf_community_datetime_modify_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.type", "==", "ip"],
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.response", "==", "Yes"],
        ],
        logical_operator='and',
        name="filter_4:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        block_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    return

def cf_rba_master_dynamic_prompt_pairing_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_rba_master_dynamic_prompt_pairing_1() called')
    
    legacy_custom_function_result_0 = [
        [
            json.loads(phantom.get_run_data(key="get_run_data:output")),
            json.loads(phantom.get_run_data(key="get_run_data:responses")),
        ],
    ]

    parameters = []

    for item0 in legacy_custom_function_result_0:
        parameters.append({
            'input_json': item0[0],
            'response': item0[1],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    
    responses = legacy_custom_function_result_0[0][1][0]
    input_json = json.loads(legacy_custom_function_result_0[0][0])
    incrementer = 0
    for item in input_json:
        parameters.append({
            'input_json': item,
            'response': responses[incrementer]
        })
        incrementer +=1
        
    ####

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "rba-master/dynamic_prompt_pairing", returns the custom_function_run_id
    phantom.custom_function(custom_function='rba-master/dynamic_prompt_pairing', parameters=parameters, name='cf_rba_master_dynamic_prompt_pairing_1', callback=filter_6)

    return

def cf_community_datetime_modify_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_datetime_modify_2() called')
    
    legacy_custom_function_result_0 = [
        [
            json.loads(phantom.get_run_data(key="get_run_data:now")),
        ],
    ]
    literal_values_0 = [
        [
            0,
            "minutes",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
        ],
    ]

    parameters = []

    for item0 in legacy_custom_function_result_0:
        for item1 in literal_values_0:
            parameters.append({
                'input_datetime': item0[0],
                'amount_to_modify': item1[0],
                'modification_unit': item1[1],
                'input_format_string': item1[2],
                'output_format_string': item1[3],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='cf_community_datetime_modify_2', callback=join_trace_email_1)

    return

def block_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_url_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_url_1' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_regex_findall_1:custom_function_result.data.group2'], action_results=results)

    parameters = []
    
    # build parameters list for 'block_url_1' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        if custom_function_results_item_1[0]:
            parameters.append({
                'url': custom_function_results_item_1[0],
                'url_category': "",
            })

    phantom.act(action="block url", parameters=parameters, assets=['zscaler'], name="block_url_1")

    return

def cf_local_regex_findall_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_regex_findall_1() called')
    
    filtered_custom_function_results_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_4:condition_1:cf_local_dynamic_prompt_pairing_1:custom_function_result.data.value'])
    literal_values_0 = [
        [
            "passthrough",
            "(http:\\/\\/|https:\\/\\/|^)(.*)",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        for item1 in filtered_custom_function_results_data_0:
            parameters.append({
                'artifact_id': item0[0],
                'input_string': item1[0],
                'input_pattern': item0[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/regex_findall", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/regex_findall', parameters=parameters, name='cf_local_regex_findall_1', callback=block_url_1)

    return

def block_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_domain() called')

    # collect data for 'block_domain' call
    filtered_custom_function_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_4:condition_2:cf_local_dynamic_prompt_pairing_1:custom_function_result.data.value'])

    parameters = []
    
    # build parameters list for 'block_domain' call
    for filtered_custom_function_results_item_1 in filtered_custom_function_results_data_1:
        if filtered_custom_function_results_item_1[0]:
            parameters.append({
                'url': filtered_custom_function_results_item_1[0],
                'url_category': "",
            })

    phantom.act(action="block url", parameters=parameters, assets=['zscaler'], name="block_domain")

    return

def block_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_ip_1() called')

    # collect data for 'block_ip_1' call
    filtered_custom_function_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_4:condition_4:cf_local_dynamic_prompt_pairing_1:custom_function_result.data.value'])

    parameters = []
    
    # build parameters list for 'block_ip_1' call
    for filtered_custom_function_results_item_1 in filtered_custom_function_results_data_1:
        if filtered_custom_function_results_item_1[0]:
            parameters.append({
                'ip': filtered_custom_function_results_item_1[0],
                'url_category': "",
            })

    phantom.act(action="block ip", parameters=parameters, assets=['zscaler'], name="block_ip_1")

    return

def run_query_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_query_2' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_3:condition_1:trace_email_1:action_result.data.*.*.RecipientAddress", "filtered-data:filter_3:condition_1:trace_email_1:action_result.data.*.*.MessageId", "filtered-data:filter_3:condition_1:trace_email_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'run_query_2' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'body': "",
                'limit': "",
                'query': "",
                'folder': "Inbox",
                'sender': "",
                'subject': "",
                'email_address': filtered_results_item_1[0],
                'get_folder_id': "true",
                'internet_message_id': filtered_results_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[2]},
            })

    phantom.act(action="run query", parameters=parameters, assets=['msgraph'], callback=filter_5, name="run_query_2")

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["run_query_2:action_result.summary.emails_matched", ">", 0],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        delete_email_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def delete_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_email_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'delete_email_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_5:condition_1:run_query_2:action_result.data.*.id", "filtered-data:filter_5:condition_1:run_query_2:action_result.parameter.email_address", "filtered-data:filter_5:condition_1:run_query_2:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'delete_email_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0] and filtered_results_item_1[1]:
            parameters.append({
                'id': filtered_results_item_1[0],
                'email_address': filtered_results_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[2]},
            })

    phantom.act(action="delete email", parameters=parameters, assets=['msgraph'], name="delete_email_1")

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.type", "==", "ip"],
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.response", "==", "Yes"],
        ],
        logical_operator='and',
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_1() called')

    formatted_data_1 = phantom.get_format_data(name='format_1')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """IP \"{0}\" would have been blocked. No blocking asset configured."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_6:condition_1:cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    add_comment_1(container=container)

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')
    
    owner_param = container.get('owner', None)

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            [owner_param, "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        decision_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_comment_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_2() called')

    phantom.comment(container=container, comment="Container has no owner detected. Please adjust owner and try again.")

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