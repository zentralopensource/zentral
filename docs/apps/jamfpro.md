# Jamf Pro

[Jamf Pro](https://jamf.com) is a widely used management software for the Apple platform. Zentral acts as a complementary solution for Jamf setups with bidirectional communication to Jamf Pro instances using the [Jamf Pro API](https://www.jamf.com/developers/apis/jamf-pro/overview/) and Jamf Webhooks.

This Jamf integration supports connection to more than one Jamf Pro instance, allowing staging and production or multi-tenancy setups within Zentral.

Zentral does support

## Use case

Connecting Zentral to Jamf adds comprehensive reporting, metrics, and dashboard capabilities that supplement Jamf-based device management. Zentral captures the state and change events for inventory, groups, and extension attributes of Jamf Pro instances providing a unified view for in-depth analysis and monitoring of all Jamf managed devices.

In addition, the integration helps extend the capabilities of Jamf Pro by incorporating capabilities from other modules in Zentral, such as Munki, Monolith, Osquery, and Santa, and linking them closely to Jamf Pro. That's part of what makes Zentral stand out as a consolidated, high-visibility platform which controls key aspects in endpoint management along the way with detailed reports, metrics, and sending enriched events to data lake and SIEM systems.

## Zentral configuration

To activate the jamf module, you need to add a `zentral.contrib.jamf` section to the `apps` section in `base.json`. 

*Note: The jamf module is ready to use and activated in the Zentral-all-in-one instances (ZAIO is a prebuilt instance to evaluate Zentral running in AWS or GCP).*  

## Instance setup

Zentral supports connecting to multiple Jamf Pro instances. You can start a new instance by clicking the button. For multitennacy setups, you would align each Jamf Pro server with a dedicated `Business unit` in Zentral. The following information needs to be provided for each Jamf Pro instance:

| Type          | Description                           | Example      | Comment   |
|---------------|---------------------------------------|--------------|-----------|
| Business unit | associate with existing business unit | default      | optional  |
| Host          | host name of the server               |              | mandatory |
| Port          | server port number                    | 443          | mandatory |
| Path          | path of the server API                | /JSSResource | mandatory |
| User          | API user name                         | -            | mandatory |
| Password      | API user password                     |              | mandatory |
| Bearer token  | Bearer token authentication           | activated    | mandatory |

The following setup items are available per Jamf instance. 

- Link to the API docs
- Setup (or remove) Webhooks automatically
- Update instance details
- Delete the instance
- Add Tag configurations


### Tag configuration

You can create tags in Zentral based on membership in Jamf Smart and Static groups in Jamf Pro. Matching pattern names are used to automatically create tags, which are then dynamically added or removed from a machine in Zentral based on which Jamf group they belong to. Zentral uses a regex to find Jamf group names. You can use a replacement pattern to generate a customized Tag name in Zentral directly with a regex match. 

To set up an automatic tagging configuration, follow these steps:
1. Click "Create"
2. Select "Group" as source
3. Choose a matching regex, e.g. filter for defined prefix matching group names will be used to automatically generate tags
4. Set replacement pattern used to generate a tag name
3. (Optional) choos from an existing Taxonomy _(You can edit the Taxonomy in Inventory > Tags section)_

### Tag config examples:

| Jamf Group name         | Taxonomy     | Regex                | Replacement     | Resulting Tag (example)       |
|-------------------------|--------------|----------------------|-----------------|-------------------------------|
| Workday                 | -            | ^Workday(.*)$        | \1              | Workday                       |      
| JamfProtect - Analytic  | Security     | ^JamfProtect - (.*)$ | JAMF \1         | Security: JAMF Analytic       |
| Apple Silicon M1        | -            | ^Apple Silicon (.*)$ | AppleSilicon-\1 | AppleSilicon-M1               |


## API permissions

Permissions needed for the Jamf contrib app. Extra permissions needed for the **machine group** and **computer extension attribute** actions are marked with a <sup>*</sup>. The webhooks permissions are only needed during setup and teardown.

|Objects|Create|Read|Update|Delete|Notes|
|---|---|---|---|---|---|
|Computer Extension Attributes|X<sup>*</sup>|X<sup>*</sup>|||Only needed if the action is configured|
|Computers||X|X<sup>*</sup>||`Update` needed only if the extension attribute action is configured|
|Mobile Devices||X||||
|Policies||X|||to enrich the webhook events
|Smart Computer Groups||X||||
|Smart Mobile Device Groups||X||||
|Static Computer Groups|X<sup>*</sup>|X|X<sup>*</sup>||`Create` and `Update` only needed if the action is configured|
|Static Mobile Device Groups||X||||
|Users|||X<sup>*</sup>||`Update` needed to update the computers. Only needed if the extension attribute action is configured.|
|Webhooks|X<sup>*</sup>|X<sup>*</sup>|X<sup>*</sup>|X<sup>*</sup>|Only needed when setting up or tearing down the webhooks from Zentral|