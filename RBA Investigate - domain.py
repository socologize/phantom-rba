"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.threat_object_type", "==", "domain"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        whois_domain_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.threat_object', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal'], callback=decision_2, name="domain_reputation_1")

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.data.*.detected_urls.*.positives", ">=", 3],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        filter_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_1() called')

    formatted_data_1 = phantom.get_format_data(name='format_1')

    phantom.pin(container=container, data=formatted_data_1, message="Suspicious Domain", pin_type="card", pin_style="red", name=None)
    join_cf_community_noop_2(container=container)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """\"{0}\" hosted URL with a score > 3 on VirusTotal"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:domain_reputation_1:action_result.parameter.domain",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    pin_1(container=container)

    return

def whois_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_domain_1() called')

    # collect data for 'whois_domain_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.threat_object', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_domain_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="whois domain", parameters=parameters, assets=['whois'], callback=whois_domain_1_callback, name="whois_domain_1")

    return

def whois_domain_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('whois_domain_1_callback() called')
    
    minus_thirty(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    cf_rba_master_normalize_lists_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def whois_epoch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_epoch() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_rba_master_normalize_lists_1:custom_function_result.data.*.item'], action_results=results )
    literal_values_0 = [
        [
            "%Y-%m-%dT%H:%M:%S",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in literal_values_0:
            parameters.append({
                'input_datetime': item0[0],
                'amount_to_modify': None,
                'modification_unit': None,
                'input_format_string': item1[0],
                'output_format_string': item1[0],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='whois_epoch', callback=join_decision_3)

    return

"""
Reduce current time by 30 days
"""
def minus_thirty(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('minus_thirty() called')
    
    container_property_0 = [
        [
            container.get("create_time"),
        ],
    ]
    literal_values_0 = [
        [
            -30,
            "days",
            "%Y-%m-%d %H:%M:%S.%f+00",
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
                'output_format_string': None,
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='minus_thirty', callback=join_decision_3)

    return

def cf_rba_master_normalize_lists_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_rba_master_normalize_lists_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['whois_domain_1:action_result.data.*.creation_date', 'whois_domain_1:action_result.parameter.domain', 'whois_domain_1:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    for item0 in action_results_data_0:
        parameters.append({
            'input_item': item0[0],
            'object_type': item0[1],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "rba-master/normalize_lists", returns the custom_function_run_id
    phantom.custom_function(custom_function='rba-master/normalize_lists', parameters=parameters, name='cf_rba_master_normalize_lists_1', callback=whois_epoch)

    return

def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_2() called')

    formatted_data_1 = phantom.get_format_data(name='format_2')

    phantom.pin(container=container, data=formatted_data_1, message="Suspicious Domain", pin_type="card", pin_style="red", name=None)
    join_cf_community_noop_1(container=container)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """Domain \"{0}\" registered less than 30 days ago"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_4:condition_1:cf_rba_master_normalize_lists_1:custom_function_result.data.*.object_type",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    pin_2(container=container)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["whois_epoch:custom_function_result.data.epoch_time", ">=", "minus_thirty:custom_function_result.data.epoch_time"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_3:condition_1:whois_epoch:custom_function_result.data.datetime_string", "==", "cf_rba_master_normalize_lists_1:custom_function_result.data.*.item"],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        filter_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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

def join_cf_community_noop_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_cf_community_noop_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['whois_epoch', 'minus_thirty']):
        
        # call connected block "cf_community_noop_1"
        cf_community_noop_1(container=container, handle=handle)
    
    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.data.*.detected_urls.*.positives", ">=", 3],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_cf_community_noop_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def cf_community_noop_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_noop_2() called')
    
    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/noop", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/noop', parameters=parameters, name='cf_community_noop_2')

    return

def join_cf_community_noop_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_cf_community_noop_2() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['domain_reputation_1']):
        
        # call connected block "cf_community_noop_2"
        cf_community_noop_2(container=container, handle=handle)
    
    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["whois_epoch:custom_function_result.data.epoch_time", ">=", "minus_thirty:custom_function_result.data.epoch_time"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_cf_community_noop_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_decision_3() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['whois_epoch', 'minus_thirty']):
        
        # call connected block "decision_3"
        decision_3(container=container, handle=handle)
    
    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_2:condition_1:domain_reputation_1:action_result.parameter.domain", "==", "artifact:*.cef.threat_object"],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_rba_master_update_artifact_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def cf_rba_master_update_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_rba_master_update_artifact_1() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:artifact:*.id'])
    literal_values_0 = [
        [
            "{ \"cef\": {\"automation_flag\": \"true\"}}",
        ],
    ]

    parameters = []

    for item0 in filtered_artifacts_data_0:
        for item1 in literal_values_0:
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

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_4:condition_1:cf_rba_master_normalize_lists_1:custom_function_result.data.*.object_type", "==", "artifact:*.cef.threat_object"],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        cf_rba_master_update_artifact_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def cf_rba_master_update_artifact_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_rba_master_update_artifact_2() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.id'])
    literal_values_0 = [
        [
            "{ \"cef\": {\"automation_flag\": \"true\"}}",
        ],
    ]

    parameters = []

    for item0 in container_data_0:
        for item1 in literal_values_0:
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
    phantom.custom_function(custom_function='rba-master/update_artifact', parameters=parameters, name='cf_rba_master_update_artifact_2')

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