# ZAIO deployment on AWS / EC2

This is a guide to run a fully functional [Zentral](https://github.com/zentralopensource/zentral) instance on **Amazon AWS**.
We will be using the **Zentral all in one** pre-build AMI (Amazon image).

*Note: We also provide a guide for a Google Cloud based setup – please look [here](../zaio-gcp).*

To follow this tutorial, you will need an admin access to the AWS web console – [Getting Started with Amazon EC2 ](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html).

*Note: This tutorial is only a first step toward a production deployment on AWS.*

## Start a new instance

In the AWS EC2 console, in one of the supported region (`us-east-1`, `us-west-2`, `eu-central-1`), click on the _Launch instances_ button. Pick a Name.

## Select a _Zentral all in one_ AMI

Click on the _Browse more AMIs_ link. Select _Community AMIs_. Use _zaio_ as search term.

Owner account ID: `221790496544`

AMIs name pattern: `zaio-ARCH-YYYYMMDD-HHMMSS`

The ZAIO AMIs are available for ARM64 and AMD64 architectures.

## Pick an instance type

You can start with a `t4g.medium` instance type – if you have picked the ARM64 AMI. We strongly advice against using any kind of "smaller" (< 4GB RAM) instances. A lot of software will be running on the instance (elasticsearch, postgres, rabbitmq, prometheus, grafana, django app, …)

Then click on the _Next: Configure Instance Details_ button.

## Key pair

It will be required for the first login. You can use an existing key pair, or create a new one. The username for the login is `ubuntu`.

## Network settings

The required open ports are 22, 80, and 443.

If you are new to this, just create a new security group for the Zentral instance.

Select _Create security group_ and tick the three boxes for `SSH`, `HTTP` and `HTTPS` (you can restrict the allowed ip ranges if you like).

## Add storage

You can start with one 20GB general purpose SSD (`gp2`) volume. But that would be only enough to store a limited amount of events. As a rule of thumb, you will need about 20GB + 1GB for every million of events stored, but that can vary a lot depending on your inventory sources, and the kind of events you are collecting.

## Launch the instance

Click on the _Launch_ button.

## Setup the domain name(s) for your instance

Zentral requires a domain name resolving to the IP address of the launched instance.

1. In the AWS console, find the public IP address of the instance that is starting. No need to wait for the instance to be available.
2. Use this IP to setup an A record. (_zentral.example.com_ for the rest of this tutorial)
3. Test the resolution of this record! You cannot move on to the next section before they are setup.

## Log onto your instance

You need the path to the key pair you have just setup. The default username is `ubuntu`.

```cmd
ssh -i ~/.ssh/TheNameOfTheKeyPairFile admin@zentral.example.com
```

**IMPORTANT** Make sure the key is only readable for your user:

```cmd
chmod 400 ~/.ssh/TheNameOfTheKeyPairFile
```

Once logged in, you can use a [command line tool to setup your instance](../zaio-setup). Because this last step is the same for a Google Cloud deployment, we have kept it on a separate wiki page.
