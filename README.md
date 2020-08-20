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

## How do I get started?

### Connect to Repo
- Navigate to Administration Settings > Source Control
- To configure Phantom to read from this repo provide the following information:
  - REPO URL: *https://github.com/kelby-shelton/phantom-rba*
  - Repo Name: *rba-master*
  - Branch Name: *master*
  - Read Only: *Check*
- Navigate to Playbooks. 
- Choose Playbooks and/or Custom Functions
- Select "Update from Source Control"

## Will this work with my environment?
The playbooks are designed in tandem with the configurations used in SA-RBA and have been tested against those configurations. To use the playbooks as-is, please check the directions below for apps and assets.

Custom functions are far more modular, and do not have any dependancies. They can be downloaded and used in any playbook.

### Prerequisites
- Phantom 4.9

### Mapping Assets
When downloading external playbooks, Phantom requires that you map your assets to the assets used within a Playbook. This process is easy thanks to the "auto-resolve" functionality of each Playbook. 

You will have to navigate to each downloaded Playbook (Playbooks > Repo Label > <Your Repo Name>), and open the playbook. Once you have opened the playbook, you will need to follow the auto-resolve steps. 

### Playbook App Integrations
- Custom Phantom Helper App (hosted at shelbertITW/phantom-rba/apps/)
- VirusTotal
