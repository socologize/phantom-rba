# FAQ

## What is Risk-Based Alerting (RBA)?
A method of alerting on anomalous behavior using Splunk Enterprise Security.

https://rbaallday.com

## What is Splunk Phantom?
Splunk's Security and IT Automation and Orchestration plaform (known as SOAR or sometimes just OAR)

## Why is this repo needed?
This is a quick-start for those that wish to fast-track their RBA Investigations and perform analysis on RBA anomalies at machine-speed.

## What does this repo contain?
Splunk Phantom playbooks that string together investigative and generic functions. The custom_functions folder contains snippets of Python code that helps enable the RBA playbooks and can be used independently. 

Playbooks can be difficult to implement as-is due to unique organizational requirements. In many cases you may wish to just download the custom_function and use the playbooks as starting ideas.

## Will this work with my environment?
Phantom 4.9 is a prerequisite and will work on any Phantom release after 4.9. The playbooks are also designed in tandem with the configurations used in SA-RBA and will work out-of-the-box if following those configurations.

## How do I get started?
- Navigate to Administration Settings > Source Control
- To configure Phantom to read from this repo provide the following information:
  - REPO URL: *https://github.com/shelbertITW/rba*
  - Repo Name: *\<your choice\>*
  - Repo Name: *master*
  - Read Only: *Check*
- Navigate to Playbooks. 
- Choose Playbooks and/or Custom Functions
- Select "Update from Source Control"
