# Jamf contrib app

## API permissions

Permissions needed for the Jamf contrib app. Extra permissions needed for the **machine group** and **computer extension attribute** actions are marked with a <sup>*</sup>. The webhooks permissions are only needed during setup and teardown.

|Objects|Create|Read|Update|Delete|Notes|
|---|---|---|---|---|---|
|Computer Extension Attributes|X<sup>*</sup>|X<sup>*</sup>|||Only needed if the action is configured|
|Computers||X|X<sup>*</sup>||`Update` needed only if the extension attribute action is configured|
|Mobile Devices||X||||
|Policies||X|||to enrich the webhook events
|Static Computer Groups|X<sup>*</sup>|X|X<sup>*</sup>||`Create` and `Update` only needed if the action is configured|
|Static Mobile Device Groups||X||||
|Users|||X<sup>*</sup>||`Update` needed to update the computers. Only needed if the extension attribute action is configured.|
|Webhooks|X<sup>*</sup>|X<sup>*</sup>|X<sup>*</sup>|X<sup>*</sup>|Only needed when setting up or tearing down the webhooks from Zentral|