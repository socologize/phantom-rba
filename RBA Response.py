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
    
    # call 'decision_2' block
    decision_2(container=container)

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
    
    # set user variable to a user or role. Defaults to "admin" if no user present
    user = container.get("owner", "admin")
    
    # message variables for phantom.prompt call
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
    phantom.custom_function(custom_function='rba-master/dynamic_prompt_pairing', parameters=parameters, name='cf_rba_master_dynamic_prompt_pairing_1', callback=cf_rba_master_dynamic_prompt_pairing_1_callback)

    return

def cf_rba_master_dynamic_prompt_pairing_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('cf_rba_master_dynamic_prompt_pairing_1_callback() called')
    
    filter_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

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

def filter_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_7() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.type", "==", "domain"],
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.response", "==", "Yes"],
        ],
        logical_operator='and',
        name="filter_7:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """Domain \"{0}\" would have been blocked. No blocking asset configured."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_7:condition_1:cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    add_comment_3(container=container)

    return

def add_comment_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_3() called')

    formatted_data_1 = phantom.get_format_data(name='format_2')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.type", "==", "file_hash"],
            ["cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.response", "==", "Yes"],
        ],
        logical_operator='and',
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_3() called')
    
    template = """File_hash \"{0}\" would have been blocked. No blocking asset configured."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_8:condition_1:cf_rba_master_dynamic_prompt_pairing_1:custom_function_result.data.value",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    add_comment_4(container=container)

    return

def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_4() called')

    formatted_data_1 = phantom.get_format_data(name='format_3')

    phantom.comment(container=container, comment=formatted_data_1)

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