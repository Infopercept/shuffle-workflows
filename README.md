Cloud security is the top priority at Amazon Web Services (AWS) and the security partner ecosystem plays a critical role in building and executing security capabilities. Infopercept Consulting is an AWS Partner which leverages open-source and building security solutions for customers.

In this post, we will share how Infopercept is leveraging Shuﬄe, an open-source general purpose security automation platform that can be used for building security playbooks.

The key elements of Shuﬄe are ease of integration with AWS services, as well as open source-like integration with Yara malware analysis. We’ll build a response playbook for malware detection and isolation.

Analyzing Objects in Amazon S3
Amazon Simple Storage Service (Amazon S3) allows you to store vast amounts of data, and objects uploaded to S3 need to be monitored for any malicious objects that can end up infecting your critical systems.

Shuﬄe is an open-source security orchestration, automation, and response (SOAR) implementation that makes automation accessible to anyone. A workﬂow will be created when a ﬁle gets placed in S3, and it will be sent to Shuﬄe via a webhook where it will be further analyzed with the help of automation.

Solution Overview
Shuﬄe fetches objects from Amazon S3 that will be scanned by the YARA rules, which are used to classify and identify malware samples by creating descriptions of malware families based on textual or binary patterns. Once any malicious indicator is found, an action will be deﬁned to either delete or quarantine it for further analysis.

The IP address of the uploader can be blocked with an additional Shuﬄe workﬂow. The solution detailed in this post leverages serverless components for fast and cost-eﬀective execution.

![image](https://user-images.githubusercontent.com/88384015/196115867-8d461158-2e5d-4afe-a304-954effcc8f63.png)
Figure 1 – Malware detection on Amazon S3 workflow.

Prerequisites
AWS account
Amazon S3 bucket
Amazon EC2 instance with 8 core, CPU 32 GB, and RAM 500 GB
AWS Lambda function
AWS Lambda Conﬁguration
The AWS Lambda configuration needs to be set so that whenever any object is uploaded to S3, the Lambda function will get triggered by sending the data to the Shuffle’s webhook. The Webhook will then receive the object data and further analysis will take place in Shuffle.

User flow: User > upload object to S3 > S3 200 OK triggers AWS Lambda function > triggers webhook > file is downloaded from within Shuﬄe.

![image](https://user-images.githubusercontent.com/88384015/196115943-0cc44f04-09bc-41b8-a7e3-444f104dffd0.png)
Figure 2 – AWS Lambda function for forwarding the object data to Shuffle for analysis.

After logging into your AWS console, go to Lambda functions and click Create function in the top right corner. Use Author from scratch and type in a name like “Shuﬄe-forwarding.” Make sure to choose Runtime as Python 3.8. Click Create function in the bottom right corner.

![image](https://user-images.githubusercontent.com/88384015/196116050-157664a7-ec4b-478e-8819-ad57c091e784.png)
Figure 3 – Creating the AWS Lambda function.

Click Add trigger in the window left of the function. In the next menu, ﬁnd Amazon S3 and before choosing the bucket you want and the Event type, click Add trigger. Note that the bucket and Lambda function have to be in the same AWS region.

![image](https://user-images.githubusercontent.com/88384015/196116155-df17dace-b469-435d-97f7-11de72a99fd3.png)
Figure 4 – Configuration for the Lambda function trigger.

Under Conﬁguration > Environment variables, click Edit. Add variable with key “SHUFFLE_WEBHOOK” and the value from earlier, and then click Save.

![image](https://user-images.githubusercontent.com/88384015/196116236-4768075a-17c4-48a5-a7b5-79477cf2245f.png)
Figure 5 – Setting up the environment variables for the Webhook.

Next, it’s time to add some code. Go to the Code tab and paste in the code below:

import urllib3
import json
import urllib.parse
import urllib3

import os
print('Loading function')
def lambda_handler(event, context):
    # Get the object from the event and show its content type bucket = event['Records'][0]['s3']['bucket']['name'] webhook = os.environ.get("SHUFFLE_WEBHOOK")
    if not webhook:
       return "No webhook environment defined: SHUFFLE_WEBHOOK" 
    http = urllib3.PoolManager()
    ret = http.request('POST', webhook, 
body=json.dumps(event["Records"][0]).encode("utf-8"))
   if ret.status != 200:
      return "Bad status code for webhook: %d" % ret.status_code 
   print("Status code: %d\nData: %s" % (ret.status, ret.data))
Click Deploy and this should now forward the request to Shuﬄe.

Amazon S3 Bucket Conﬁguration for Scanning
Create an Amazon S3 bucket where objects will be monitored with YARA rules. If a malicious object is detected, the object will be quarantined and the IP address can be captured to block and investigate further.

Enable the server access logging and provide the target bucket where you want to save the logs.

![image](https://user-images.githubusercontent.com/88384015/196116346-f7de8928-a05e-4c53-a28a-ab99780c8eb9.png)
Figure 6 – Logging configurations for the monitored S3 bucket.

Setting Up Shuﬄe SOAR
Shuﬄe will be installed in a container environment using Docker:

Make sure you have Docker and docker-compose installed in your Amazon Elastic Compute Cloud (Amazon EC2) instance.
Download Shuﬄe:
git clone https://github.com/frikky/Shuffle
cd Shuffle
Fix prerequisites for the Opensearch database (Elasticsearch):
mkdir shuffle-database
sudo chown -R 1000:1000 shuffle-database
Run docker-compose:
docker-compose up -d
When done, follow the below steps:

After installation, go to http://localhost:3001 (or your server name – https is on port 3443).
Set up your admin account (username and password). Shuﬄe doesn’t have a default username and password.
Sign in with the same username and password. Go to /apps and see if you have any apps yet. If not, you may need to conﬁgure proxies.
Check out https://shuﬄer.io/docs/conﬁguration as it has lots of useful information to get started.
Creating the Workﬂow in Shuﬄe
Workﬂows are the backbone of Shuﬄe, empowering you to automate your daily tasks by with a simple interface. Workﬂows use apps, triggers, conditions, and variables to make powerful automations in no time.

Clone the workﬂow from the following link: https://github.com/Infopercept/shuﬄe-workﬂows

Once the ﬁle is downloaded, you can upload the ﬁle from Shuﬄe console.

![image](https://user-images.githubusercontent.com/88384015/196116428-ad3c972c-47fd-4f1b-a826-4b0170f6e9ba.png)
Figure 7 – Shuffle workflow for the S3 malware scanning.

The icons placed here depicts our workﬂow, and the S3 events will be collected and sent to Shuﬄe via webhook. This will notify Shuﬄe of any new object.

Breakdown of the Workﬂow
A webhook from the Triggers panel will bring the events for correlation, when the object is placed in your S3 bucket. Shuﬄe tools will be used for setting various conditions and will help in correlation. Here, it will be used for parsing the URL of S3 object.

![image](https://user-images.githubusercontent.com/88384015/196116473-c5b7bf39-9b0e-49df-8fc9-d6abe53f554d.png)
Figure 8 – Connecting webhook to shuffle tools.

Once the URL is parsed, the objects have to be fetched from the parsed URL.

![image](https://user-images.githubusercontent.com/88384015/196116518-6b982e4d-853b-4a23-823f-c02e47aab571.png)
Figure 9 – Fetching the S3 object for analysis.

To fetch objects from S3, it needs to be authenticated. Provide a name, access key, secret key, and region. Once the objects start to fetch from S3, YARA rules will start scanning if any object is placed in the S3 bucket.

![image](https://user-images.githubusercontent.com/88384015/196116600-c16602af-eaa2-49cf-9954-f611ef2cae1d.png)
Figure 10 – Object scanned by the YARA rules.

Any malicious object detected will be deleted automatically; malicious ﬁles can also be quarantined for further analysis.

Let’s take it a step further and explore how the Shuﬄe orchestrator can be leveraged for diﬀerent ﬂows. Consider that not only the malicious ﬁle needs to be detected, but the uploader IP address should be captured and blocked. Also, when an IP address is blocked put an alert in a slack channel.

Check out this reference link to conﬁgure Slack authentication application.

Add the malicious IP address to Amazon GuardDuty threat list to build threat intel.

![image](https://user-images.githubusercontent.com/88384015/196116636-6872db99-47f9-4493-b92a-e22724917a1b.png)
Figure 11 – Adding the malicious IP address to GuardDuty.

It will be downloading the threat list add the IP address detected and upload the threat list again to the S3 bucket.

![image](https://user-images.githubusercontent.com/88384015/196116688-7af60389-5dd2-4672-9297-d291b9bf55de.png)
Figure 12 – Sending the alert notification to the Slack channel.

That’s it! Now save the workflow and you are good to go.

Conclusion<br>
Through the setup detailed in this post, you can secure Amazon S3 from getting infecting through malicious threat actors using this serverless solution. The workflow scans files from YARA rules and sends malicious IP addresses to Amazon GuardDuty so adversaries do not affect the environment in the future. You can delete or even quarantine files, along with blocking the suspicious IP addresses.

Shuﬄe provides ﬂexibility to build custom response automation ﬂows, enabling you to build your own playbooks. Infopercept provides implementation and consultation services to help you build your own playbooks.

