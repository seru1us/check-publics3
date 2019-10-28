# check-publics3

[![Build Status](https://travis-ci.org/seru1us/check-publics3.svg?branch=master)](https://travis-ci.org/seru1us/check-publics3)

# Purpose and Overview

This documentation is supporting material for a coding exercise I was asked to perform for a potential employer. At a high level, the code's purpose is to check for publicly available s3 buckets. A few things to keep in mind when reading this code:
  - I mostly write code for customers, and am used to liberally commenting so others can change it easily (never had a complaint about that). For granular details and a step-by-step analysis, please refer to the source.
  - The assumption was that this would be written in a matter of hours, so there are a number of notes and TODOs included where I would do something better given more time. With that said, I stayed true to the time allotment. 


The technical requriements and use cases that were requested:
  - Write a command-line tool that will check for public s3 buckets
  - The tool should maintain state for buckets that have been detected previously
  - The tool should generate output whenever a new public bucket is detected, or if a previously non-public bucket changed to public
  - Use any language of choice
  - Using the AWS API or libraries are allowed as well as consulting any online source or documentation

### Design Decisions and Architecture
When considering how to architect this use tool, I decided to make a simple CLI tool that can be ran without any parameters. The main reason I created it in this way were due to the two requirements I was given: "make it a command-line tool" and "have it check for publicly accessible buckets". Having said that, I would like to point out that in a production environment I would suggest using a different method to simply alert and respond to a discovered public bucket.

While this application needs to be ran on a scheduled or interactive basis, for security events such as s3 ACL changes, best practices dictate that incidents are handled in as close to real-time as possible. In this instance, I would suggest [utilizing s3 event notifications](https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html) to audit changes and creation of s3 buckets. By listening for real-time events for changes, quick response to public s3 buckets can resolve any configuration issues or unauthorized changes in stored data.

The Caveat to this is it requires additional AWS infrastructure- s3 event notifications integrate specifically with the following AWS platforms:
  - [Amazon Simple Notification Service (Amazon SNS) ](https://aws.amazon.com/sns/)
  - [Amazon Simple Queue Service (Amazon SQS) queue](https://aws.amazon.com/sqs/)
  - [AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/with-s3.html)

### Installation and Best Practice Suggestions
OS Package Requirements: Python3, pip3, python3-venv (suggested)
External Python Library Requirements: boto3

As always, when running Python3 code it is suggested to use a [VirtualEnv](https://docs.python.org/3/tutorial/venv.html) for better scaling and security. Ensure that Python3, Pip3 (package manager), and VirtualEnv are all installed with the following examples.

Debian/Ubuntu:
```sh
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

CentOS/RHEL:
```sh
sudo yum update
sudo yum install python3 python3-pip
sudo pip3 install virtualenv
```

In order to create a vritualenv for this script, clone this repo (optional) and then navigate to your directory with the following:

```sh
git clone https://github.com/seru1us/check-publics3
python3 -m venv venv
source venv/bin/activate
```
In order to install boto3, use the following pip command:

```sh
pip3 install -r requirements.txt
```

The versions reflected in the requirements.txt are the same ones the script was tested with.

### AWS IAM Permissions for Service Account
In order to align with security best practices Least Privilege and Separation of Duties, it is suggested to create a new IAM service account only with permissions to query the ACLs for s3 buckets. In order to do so, the following Policy json was created to only allow the required permissions for the script to work:

```sh
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "XXXXXXXXXXXXXXX",
      "Action": [
        "s3:GetBucketAcl",
        "s3:ListAllMyBuckets",
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

As you can see, the script needs access to query all available buckets, as well as their ACL attributes. This policy can be created [by navigating here](https://console.aws.amazon.com/iam/home?region=us-east-2#/policies$new) and clicking on the "json" tab. Once the policy has been created, create a new user and attach the policy to them. Once the user is provisioned, see the next section for configuring boto3.

### boto3 Prerequisites 
boto3 needs to be initialized before being ran for the first time, so it can properly store the AWS Access Key ID and Secret Access Key for API authentication. Fore more information, [visit this link](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html) or configure the application interactively by running the following:

```sh
aws configure
```


#### Note: 
In an enterprise environment this is considered a sensitive secret, and should be treated as such. Using a secrets management platform such as Hashicorp Vault or Conjur is highly reccomended. 

### Usage
Quite simple, just run the script without any parameters. 

```sh
python3 check-publics3.py
```

### Logging, Storage and Notifications
The persistent storage is kept in a very simple sqlite database that is provisioned if not found at the time of the script execution. 

Notifications are handles via syslog output. Currently, the implementation is very basic and is a large stretch from [proper rfc5424 standards](https://tools.ietf.org/html/rfc5424), but can still be integrated with any enterprise logging and alerting platform to properly create a formal incident. 

Best practices defer aggregating security events, such as the events this script creates, to a centralized platform or SIEM to be further ingested for auditing. 

