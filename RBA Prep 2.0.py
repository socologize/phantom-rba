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
    
    # call 'decision_6' block
    decision_6(container=container)

    return

def format_splunk_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_splunk_query() called')
    
    template = """index=risk risk_object=\"{0}\"
| where (_time >={1}+21600 AND _time<={2}+21600)
|  eval source=replace(source,\"\\w+\\s+-\\s+\\w+\\s+-\\s+([^-]+)\\s+-.*\",\"\\1\")
| stats earliest(_time) as _time values(*) as * by source, threat_object | fields - user_* src_user_* src_* dest_* dest_user_* info_* search_* splunk_* tag* risk_modifier* risk_rule* sourcetype timestamp index next_cron_time"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.risk_object",
        "filtered-data:filter_1:condition_1:artifact:*.cef.info_min_time",
        "filtered-data:filter_1:condition_1:artifact:*.cef.info_max_time",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_splunk_query")

    fetch_risk_rules(container=container)

    return

def fetch_risk_rules(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('fetch_risk_rules() called')

    # collect data for 'fetch_risk_rules' call
    formatted_data_1 = phantom.get_format_data(name='format_splunk_query')

    parameters = []
    
    # build parameters list for 'fetch_risk_rules' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['es-rba'], callback=cf_rba_master_parse_risk_results_1, name="fetch_risk_rules")

    return

def set_container_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_container_low() called')

    phantom.set_severity(container=container, severity="Low")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
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

def set_container_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_container_high() called')

    phantom.set_severity(container=container, severity="High")

    return

def set_container_med(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_container_med() called')

    phantom.set_severity(container=container, severity="Medium")

    return

def playbook_rba_master_rba_master_RBA_Investigate_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_rba_master_rba_master_RBA_Investigate_1() called')
    
    # call playbook "rba-master/RBA Investigate", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="rba-master/RBA Investigate", container=container)

    return

def update_artifact_sev_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
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

def update_artifact_sev_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
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

def update_artifact_sev_med(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
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

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.event_id", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_splunk_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def cf_rba_master_parse_risk_results_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_rba_master_parse_risk_results_1() called')
    
    action_results_data_0 = phantom.collect2(container=container, datapath=['fetch_risk_rules:action_result.data', 'fetch_risk_rules:action_result.parameter.context.artifact_id'], action_results=results )

    parameters = []

    action_results_data_0_0 = [item[0] for item in action_results_data_0]

    parameters.append({
        'search_json': action_results_data_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "rba-master/parse_risk_results", returns the custom_function_run_id
    phantom.custom_function(custom_function='rba-master/parse_risk_results', parameters=parameters, name='cf_rba_master_parse_risk_results_1', callback=cf_rba_master_add_artifact_with_tags_1)

    return

def cf_rba_master_add_artifact_with_tags_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_rba_master_add_artifact_with_tags_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['cf_rba_master_parse_risk_results_1:custom_function_result.data.*.artifact.cef', 'cf_rba_master_parse_risk_results_1:custom_function_result.data.*.artifact.tags', 'cf_rba_master_parse_risk_results_1:custom_function_result.data.*.artifact.name'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]
    literal_values_0 = [
        [
            "informational",
            "risk_rule",
            "True",
        ],
    ]

    parameters = []

    for item0 in custom_function_result_0:
        for item1 in literal_values_0:
            for item2 in container_property_0:
                parameters.append({
                    'cef': item0[0],
                    'tags': item0[1],
                    'severity': item1[0],
                    'container_id': item2[0],
                    'label': item1[1],
                    'name': item0[2],
                    'run_automation': item1[2],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "rba-master/add_artifact_with_tags", returns the custom_function_run_id
    phantom.custom_function(custom_function='rba-master/add_artifact_with_tags', parameters=parameters, name='cf_rba_master_add_artifact_with_tags_1')

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.label", "==", "risk_rule"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        playbook_rba_master_rba_master_RBA_Investigate_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

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