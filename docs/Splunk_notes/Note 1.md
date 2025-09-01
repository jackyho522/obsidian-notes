## Planning for Infrastructure and Resource Scalability
What is your current logging infrastructure?<br/>
What logs will be ingested into Splunk?<br/>
What are the retention periods for each of those logs you mentioned?<br/>
[Reference](https://splunk-sizing.soclib.net/)<br/>
What levels of access will be required to the data?<br/>
Do you have an estimate of the daily amounts for your data sources?<br/>
Estimate the disk space requirements.<br/>
Assume the following compression factors for all of the data sources: <br/>
• 15% compression for rawdata <br/>
• 35% compression for index files<br/>

## License
Take the upper limit. Example:<br/>
315 gb = 315 x 1.10 = 346.5 = 350 gb license.<br/>
If the excess usage exceeds ten percent (10%) of the Licensed Capacity, then Customer will also pay Splunk's reasonable costs of conducting the audit.


## Troubleshooting Splunk
### General 
```bash
a. How are the servers connected? 
index=_internal sourcetype=splunkd connection* | stats count by sourceIp, host, destPort 
index=_internal sourcetype=splunkd connection* | stats max(_time) as lastEventTime by host
| convert ctime(lastEventeTime)
```
```bash
b. Which servers are forwarding? 
index=_internal sourcetype=splunkd tcpout_connections | stats count by host, destIp, destPort | rename host as forwarder, destIp as indexer, destPort as listening_port 
index=_internal sourcetype=splunkd metrics group=tcpin_connections connectionType=cooked* | stats sum(kb) by hostname, fwdType, lastIndexer 
```
```bash
c. Are the forwarders also deployment clients? index=_internal sourcetype=splunkd component=DC* Handshake | stats count by host 
```
```bash
d. Where is the deployment server? index=_internal sourcetype=splunkd component=DeployedApplication url=* | table host url 
```
```bash
e. What apps have been deployed to the forwarders from the deployment server and when? 
index=_internal sourcetype=splunkd component=DeployedApplication installing | stats count latest(_time) AS latest_time by host app | convert ctime(latest_time)
```
```
f. permission issue/specific user
$SPLUNK_HOME/bin/splunk enable boot-start -user bob
chown -RP splunk:splunk /opt/splunk
```
```
g. Is client phoning home?
index=_internal sourcetype=splunkd connection* | stats max(_time) as lastEventTime by host
| convert ctime(lastEventTime)
```
```
h. Show alert list in query?
| rest/servicesNS/-/-/saved/searches | search alert.track=1 | fields title description search disabled triggered_alert_count actions action.script.filename alert.severity cron_schedule
```
```
#Check email
| rest /services/saved/searches
| search action.email.to=* action.email=1 disabled=0
| rename eai:acl.app as Application, title as "Alert Name", triggered_alert_count as "Times Triggered Conditions Met", splunk_server as Host, action.email.to as "Sent To"
| table Application, "Alert Name", description, "Times Triggered Conditions Met", Host, "Sent To", search, actions, action.script.filename, action.email.subject, action.email.subject.alert, alert.severity, cron_schedule
```
```
grep alert config
find . -name savedsearches.conf -exec grep -iH "Basic" {} \;
find . -name savedsearches.conf
```
[Reference](https://community.splunk.com/t5/Alerting/How-can-I-query-to-get-all-alerts-which-are-configured/m-p/288845)<br/>
```
i. Check License usage (real time usage ONLY)?
index=_internal source=*license_usage.log type="Usage"    | eval indexname = if(len(idx)=0 OR isnull(idx),"(UNKNOWN)",idx) | eval sourcetypename = st | bin _time span=1d | stats values(poolsz) as poolsz sum(b) as b by _time, pool, indexname, sourcetypename | eval GB=(b/1024/1024/1024) | eval pool=(poolsz/1024/1024/1024) | fields _time, indexname, sourcetypename, GB, pool
| stats sum(GB) by indexname, _time
| eval license_usage_percentage = (GB_used / 250) * 100
```
```
j. Check Datamodel
|  datamodel Authentication search
|  search Authentication.user=*
|  stats count by Authentication.user
```
## Diag
Generate Diag: <br/>
Navigate to Settings > Instrumentation <br/>
Click New Diag <br/>
Index New Diag:<br/>
Settings > Add Data > Monitor<br/>
Select the Index Once option and click Next<br/>
```
Determine the Splunk version and its system information
index=diag source=*systeminfo.txt (version OR Uname OR "process listing")
```
```
to list the apps installed and determine their running status, search (All time)
index=diag source=*etc/apps/*app.conf | rex field=source "etc/apps/(?\w+)/" | rex field=_raw "label.\=.(?.+)" | stats values(label) as Name, values(state) as State, values(is_visible) as Visible by folderName
```
## Indexing Issues
