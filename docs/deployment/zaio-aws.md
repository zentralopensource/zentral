# ZAIO deployment on AWS / EC2

This is a guide to run a fully functional [Zentral](https://github.com/zentralopensource/zentral) instance on **Amazon AWS**. 
We will be using the **Zentral all in one** pre-build AMI (Amazon image).

*Note: We also provide a guide for a Google Cloud based setup – please look [here](../zaio-gcp).*

To follow this tutorial, you will need an admin access to the AWS web console – [Getting Started with Amazon EC2 ](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html).

*Note: This tutorial is only a first step toward a production deployment on AWS.*

*Note: We have uploaded a [video](https://www.youtube.com/watch?v=oH2kz3JOgzs) to go along this tutorial.*

## Find the _Zentral all in one_ image

You can find the links to start the latest images in the description of [the latest release](https://github.com/zentralopensource/zentral/releases). Pick the one in your favorite region.

*Note: "Zentral all in one" AMI is not available in all AWS regions*

## Pick an instance type

You can start with a `t2.medium` instance type. We strongly advice against using any kind of "smaller" instances. A lot of software will be running on the instance (ELK, postgres, prometheus, django app, …)

Then click on the _Next: Configure Instance Details_ button.

## Configure instance details

You can skip this form to run a default instance in the default VPC.

Click on the _Next: Add Storage_ button.

If you'd like to create a new, distinct VPC:

1. You'll be first prompted to create/assign a subnet (local range, smallest is 28 so may as well start with /26 for entire new VPC) 
2. Follow the following instructions afterwards so that it gets a public IP and routing from the internet works

*Here is a link to the documentation about [VPC Internet Gateway](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html#working-with-igw), if you want to dig deeper.*


## Add storage

You can start with one 8GB general purpose SSD volume. But that would be only enough to store a limited amount of events. As a rule of thumb, you will need about 7GB + 1GB for every million of events stored, but that can vary a lot depending on your inventory sources, and the kind of events you are collecting.

Click on the _Next: Add Tags_ button.

## Add tags

You can skip this section.

Click on the _Next: Configure Security Group_ button.

## Configure security groups

The required open ports are 22, 80, and 443.

If you are new to this, just create a new security group for the Zentral instance:

1. Pick a name and a description
2. Add a rule for SSH. (you can restrict the allowed ip ranges if you like)
3. Add a rule for HTTP
4. Add a custom TCP rule for port 443 (HTTPS). Do not forget the ip range – Unrestricted IPv4/v6: `0.0.0.0/0, ::/0`

*Here is a link to the documentation about the [Security Groups](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_SecurityGroups.html), if you want to dig deeper.*

Click on the _Next: Review and Launch_ button.

## Review and launch

You can review the settings for the new instance.

Click on the _Launch_ button. A modal will popup, to pick or create a ssh key pair to be able to log into the instance. If you do not have a ssh key pair yet:

1. select _Create a new key pair_
2. give it a name
3. click on the _Download Key Pair_ button
4. save the file in your `$HOME/.ssh` dir for example
5. make the file readable only for your user `chmod 0600 ~/.ssh/TheNameOfTheKeyPairFile`

Once you have a ssh key pair, click on the _Launch Instances_ button, and your instance will start!

## Setup the domain name(s) for your instance

Zentral requires at leat one domain name resolving to the IP address of the launched instance. If you want to experiment with the MDM, you will need a second domain name (to separate the endpoints requiring client certificate authentication).

1. In the AWS console, [find the public IP address of the instance](https://youtu.be/oH2kz3JOgzs?t=69) that is starting. No need to wait for the instance to be fully up.
2. Use this IP to setup a first required A record. (_zentral.example.com_ for the rest of this tutorial)
3. You can setup a second A record pointing to be able to test all the Zentral functionalities. (_zentral-clicertauth.example.com_ for the rest of this tutorial)
4. Test the resolution of these records! You cannot move on to the next section before they are setup.

## Log onto your instance

You need the path to the key pair you have just setup. The default username is `ubuntu`.

```cmd
ssh -i ~/.ssh/TheNameOfTheKeyPairFile ubuntu@zentral.example.com
```

Once logged in, you can use a [command line tool to setup your instance](../zaio-setup). Because this last step is the same for a Google Cloud deployment, we have kept it on a separate wiki page.
