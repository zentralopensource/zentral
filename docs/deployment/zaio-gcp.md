# ZAIO deployment on GCP

This is a guide to run a fully functional [Zentral](https://github.com/zentralopensource/zentral) instance on **Google Cloud Platform**. 
We will be using the **Zentral all in one** pre-build image.

*Note: We also provide a guide for an AWS based setup - please look [here](../zaio-aws).*

To follow this tutorial, you will need an admin access to the Google Cloud Platform console ([Getting started](https://cloud.google.com/gcp/getting-started/))

*Note: This tutorial is only a first step toward a production deployment on Google Cloud.*

## Google Cloud Platform setup

You will need to pick a **project**, and think about a **region** where you want to store the image, and start the instance. For the rest of this tutorial, it will be `My First Project` and `europe-west-3`.

## Setup the firewall rules

*Note: We will be working with the default VPC. This is not recommended for production.*

At the minimum, for this tutorial, we will need access to the 22, 80, and 443 ports.

## Create the instance

Open the [Create an instance](https://console.cloud.google.com/compute/instancesAdd) form.

In the **Name** field, specify a unique name for your instance. We will use `zentral-all-in-one`.

Select a **Region** and a **Zone**.

The default _General-purpose_ **Machine family**, and _e2-standard-2_ **Machine type** are OK to test Zentral.

![Create instance form first sections](../../images/deployment/zaio-gcp/create_instance_top_form.png)

In the **Boot disk** section, click on the [Change] button, go to the [Custom images] tab. Set `sublime-delight-encoder` or `Zentral Pro Services` as the project, and in the dropdown, select the latest `zaio-ARCH-YYYYMMDD-HHMMSS`.

![Select zentral-all-in-one custom image](../../images/deployment/zaio-gcp/select_image.png)

You can start with one 10GB SSD persistent disk. But that would be only enough to store a limited amount of events. As a rule of thumb, you will need about 9GB + 1GB for every million of events stored, but that can vary a lot depending on your inventory sources, and the kind of events you are collecting.

This is what you should see in the *Boot disk* section:

![zentral-all-in-one-image-selected](../../images/deployment/zaio-gcp/boot_disk_selected.png)

We will use the **Compute engine default service account** and the **default access scopes**. Again, not recemmended for production.

In the **Firewall** section, tick the _Allow HTTP traffic_ and _Allow HTTPS traffic_ boxes.

Click on the **Create** button to launch the instance.

## Setup the domain name(s) for your instance

Zentral requires at leat one domain name resolving to the IP address of the launched instance. If you want to experiment with the MDM, you will need a second domain name (to separate the endpoints requiring client certificate authentication).

1. In the Google Cloud console, [find the public IP address of the instance](https://console.cloud.google.com/compute/instances) that is starting. No need to wait for the instance to be fully up.
2. Use this IP to setup the required A record. (_zentral.example.com_ for the rest of this tutorial)
4. Test the resolution of this record! You cannot move on to the next section before they are setup.

## Log onto your instance

You can open a ssh session via the Google Cloud. Click on the instance in the [list of all instance](https://console.cloud.google.com/compute/instances). At the top of the instance page, open the **Remote access / SSH** menu and select _Open in browser window_. A new tab will open and a ssh session will start.

![open ssh in browser window](../../images/deployment/zaio-gcp/open_ssh_in_browser_window.png)

Once logged in, you can use a [command line tool to setup your instance](../zaio-setup). Because this last step is the same for a AWS deployment, we have kept it on a separate wiki page.
