"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_local_normalize_lists_1' block
    cf_local_normalize_lists_1(container=container)

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ip_reputation_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_1' call
    filtered_custom_function_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_3:cf_local_normalize_lists_1:custom_function_result.data.items.*.ip'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for filtered_custom_function_results_item_1 in filtered_custom_function_results_data_1:
        if filtered_custom_function_results_item_1[0]:
            parameters.append({
                'ip': filtered_custom_function_results_item_1[0],
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], name="ip_reputation_1")

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('domain_reputation_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_reputation_1' call
    filtered_custom_function_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:cf_local_normalize_lists_1:custom_function_result.data.items.*.domain'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for filtered_custom_function_results_item_1 in filtered_custom_function_results_data_1:
        if filtered_custom_function_results_item_1[0]:
            parameters.append({
                'domain': filtered_custom_function_results_item_1[0],
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal'], callback=format_domain_note, name="domain_reputation_1")

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('file_reputation_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'file_reputation_1' call
    filtered_custom_function_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_2:cf_local_normalize_lists_1:custom_function_result.data.items.*.hash'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for filtered_custom_function_results_item_1 in filtered_custom_function_results_data_1:
        if filtered_custom_function_results_item_1[0]:
            parameters.append({
                'hash': filtered_custom_function_results_item_1[0],
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], name="file_reputation_1")

    return

def format_domain_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('format_domain_note() called')
    
    template = """%%
----------- Domain: {0} -----------<li>Associated URLs: {1}</li><li>Safety Score: {2}</li><li>Adult Content: {3}</li><li>Verdict: {4}</li><br>-----------------------------------------------------<br>
%%"""

    # parameter list for template variable replacement
    parameters = [
        "domain_reputation_1:action_result.parameter.domain",
        "domain_reputation_1:action_result.summary.detected_urls",
        "domain_reputation_1:action_result.data.*.Webutation domain info.Safety score",
        "domain_reputation_1:action_result.data.*.Webutation domain info.Adult content",
        "domain_reputation_1:action_result.data.*.Webutation domain info.Verdict",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_domain_note")

    add_note_1(container=container)

    return

def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('add_note_1() called')

    formatted_data_1 = phantom.get_format_data(name='format_domain_note__as_list')

    note_title = "Domain Reputation"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def cf_local_normalize_lists_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('cf_local_normalize_lists_1() called')

    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.threat_object', 'artifact:*.cef.threat_object_type', 'artifact:*.id'])

    parameters = []

    for item0 in container_data_0:
        parameters.append({
            'var': item0[0],
            'object_type': item0[1],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/normalize_lists", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/normalize_lists', parameters=parameters, name='cf_local_normalize_lists_1', callback=cf_community_debug_1)

    return

def cf_community_debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('cf_community_debug_1() called')

    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_local_normalize_lists_1:custom_function_result.data.items'], action_results=results )

    parameters = []

    custom_function_result_0_0 = [item[0] for item in custom_function_result_0]

    parameters.append({
        'input_1': custom_function_result_0_0,
        'input_2': None,
        'input_3': None,
        'input_4': None,
        'input_5': None,
        'input_6': None,
        'input_7': None,
        'input_8': None,
        'input_9': None,
        'input_10': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/debug", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/debug', parameters=parameters, name='cf_community_debug_1', callback=filter_3)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_normalize_lists_1:custom_function_result.data.items.*.domain", "!=", ""],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_normalize_lists_1:custom_function_result.data.items.*.hash", "!=", ""],
        ],
        name="filter_3:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_normalize_lists_1:custom_function_result.data.items.*.ip", "!=", ""],
        ],
        name="filter_3:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_normalize_lists_1:custom_function_result.data.items.*.url", "!=", ""],
        ],
        name="filter_3:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        detonate_url_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    return

def detonate_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('detonate_url_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_url_1' call
    filtered_custom_function_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_4:cf_local_normalize_lists_1:custom_function_result.data.items.*.url'])

    parameters = []
    
    # build parameters list for 'detonate_url_1' call
    for filtered_custom_function_results_item_1 in filtered_custom_function_results_data_1:
        if filtered_custom_function_results_item_1[0]:
            parameters.append({
                'url': filtered_custom_function_results_item_1[0],
                'private': True,
            })

    phantom.act(action="detonate url", parameters=parameters, assets=['urlscan'], callback=format_6, name="detonate_url_1")

    return

def format_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('format_6() called')
    
    template = """`URL Detonated: {0}`

![]({0})"""

    # parameter list for template variable replacement
    parameters = [
        "detonate_url_1:action_result.data.*.task.screenshotURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_6")

    add_note_2(container=container)

    return

def add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('add_note_2() called')

    formatted_data_1 = phantom.get_format_data(name='format_6')

    note_title = "URL Screenshot"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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