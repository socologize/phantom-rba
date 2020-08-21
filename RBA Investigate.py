"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    # call 'decision_2' block
    decision_2(container=container)

    # call 'decision_3' block
    decision_3(container=container)

    # call 'decision_4' block
    decision_4(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.threat_object_type", "==", "ip"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        playbook_rba_master_rba_master_RBA_Investigate_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def playbook_rba_master_rba_master_RBA_Investigate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_rba_master_rba_master_RBA_Investigate_ip_1() called')
    
    # call playbook "rba-master/RBA Investigate - ip", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="rba-master/RBA Investigate - ip", container=container, name="playbook_rba_master_rba_master_RBA_Investigate_ip_1", callback=join_decision_5)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.threat_object_type", "==", "domain"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        playbook_rba_master_rba_master_RBA_Investigate_domain_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def playbook_rba_master_rba_master_RBA_Investigate_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_rba_master_rba_master_RBA_Investigate_domain_1() called')
    
    # call playbook "rba-master/RBA Investigate - domain", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="rba-master/RBA Investigate - domain", container=container, name="playbook_rba_master_rba_master_RBA_Investigate_domain_1", callback=join_decision_5)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.threat_object_type", "==", "command"],
            ["artifact:*.cef.threat_object_type", "==", "process"],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        playbook_rba_master_rba_master_RBA_Investigate_process_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def playbook_rba_master_rba_master_RBA_Investigate_process_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_rba_master_rba_master_RBA_Investigate_process_1() called')
    
    # call playbook "rba-master/RBA Investigate - process", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="rba-master/RBA Investigate - process", container=container, name="playbook_rba_master_rba_master_RBA_Investigate_process_1", callback=join_decision_5)

    return

def playbook_rba_master_rba_master_RBA_Investigate_file_hash_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_rba_master_rba_master_RBA_Investigate_file_hash_1() called')
    
    # call playbook "rba-master/RBA Investigate - file_hash", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="rba-master/RBA Investigate - file_hash", container=container, name="playbook_rba_master_rba_master_RBA_Investigate_file_hash_1", callback=join_decision_5)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.threat_object_type", "==", "file_hash"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        playbook_rba_master_rba_master_RBA_Investigate_file_hash_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.automation_flag", "==", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        playbook_rba_master_RBA_Response_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def join_decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_decision_5() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(playbook_names=['playbook_rba_master_rba_master_RBA_Investigate_ip_1', 'playbook_rba_master_rba_master_RBA_Investigate_domain_1', 'playbook_rba_master_rba_master_RBA_Investigate_process_1', 'playbook_rba_master_rba_master_RBA_Investigate_file_hash_1']):
        
        # call connected block "decision_5"
        decision_5(container=container, handle=handle)
    
    return

def playbook_rba_master_RBA_Response_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_rba_master_RBA_Response_1() called')
    
    # call playbook "rba-master/RBA Response", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="rba-master/RBA Response", container=container)

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