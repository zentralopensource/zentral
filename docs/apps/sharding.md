# Sharding 

## Percentage based, phased rollout

Zentral offers a powerful sharding feature that enables flexible rollout strategies for configurations and Munki-based, managed software installations. Sharding, also known as percentage rollout, is a phased approach to rolling out new configurations, new products (apps), or deploying updates to existing products. This documentation provides an overview of how sharding works in Zentral and provides examples of how it can be used to effectively manage software deployments.

## Overview

Zentral's sharding feature is designed to facilitate tight controlled rollouts for configurations as well as Munki-based app installs and patching. You can manage both the initial installation of software and the incremental rollout of updates with percentage sharding based on dynamic munki manifests and custom group assignments. The sharding value can be specified based on individual packages (pkg) within the associated pkginfo on the munki_repo level or tag based sharding can be managed in the GUI, both can be integrated into GitOps workflows.

When introducing new products, it is crucial to ensure proper testing and validation before a full deployment. This is where a phased rollout approach comes in. By deploying config or software to a small percentage of users initially, it becomes possible to gather feedback and gradually increase the rollout to larger groups. This approach helps identify and mitigate any issues that may arise during the rollout, minimizing disruption to users.

For existing products, the rollout strategy depends on the nature of the update or patch being deployed. An essential configuration, critical security patches, or bug fixes may require a simultaneous rollout to all users to minimize risk. On the other hand, non-critical updates may benefit from a more gradual rollout, involving deployment to a small group of users first and gradually increasing the rollout to minimize disruptions and identify potential issues.


## Monolith Sharding
Zentral's sharding feature provides precise planning, rollout, and reporting options for software deployments using Munki. It offers two main options: sharding and tag-based sharding. These options allow administrators to define specific rollout parameters and measure success using key performance metrics. These options are available from the start of software deployment in Munki and can be assigned in the sub-manifest.

### Sharding - Understanding the Moving Parts
Zentral's sharding feature dynamically maps shard values to computers for each product. This mapping enables verification of the desired and current status of software titles per computer with a detailed view in the GUI. By providing greater control over software distribution, sharding helps reduce Munki warnings that occur when a software title is not found in the catalog on each run.



### New Products
When introducing a new product, it is recommended to include it in all catalogs. Zentral's sub-manifests offer flexibility in managing software by allowing default/managed/optional installation, uninstallation, and upgrades. Furthermore, tags can be utilized to include or exclude specific machines from the rollout scope.

Excluded tags effectively stop further processing before evaluating anything else. By tagging machines as excluded, administrators can ensure that specific machines, such as VIPs, do not receive the software during the initial stages of the rollout.

The "Default shard" value comes into play when no shards are specified at the tag level. It represents the percentage of the fleet that will receive the software. Administrators can easily increment this value to gradually increase the rollout.

For more refined rollouts, administrators can utilize "Tag shards." By using tags and assigning numerical values falling within the specified modulo range, administrators can define precise rollout percentages for machines with specific tags.

The following table provides an overview of the effect of excluding tagged machines and the precedence of different rollout options:


| Precendence | Excluded Tags | Default Shard | Tag Shards | Effect                                 |
|-------------|---------------|---------------|------------|----------------------------------------|
| 1           | Yes           | -             | -          | Short-circuits processing              |
| 2           | No            | Yes           | -          | Percentage of fleet receiving software |
| 3           | No            | No            | Yes        | Percentage based on Tag assignment     |


### Existing Products
For existing products, Tags are be particularly helpful as well. Tags can be used to group and categorize clients into Munki tracks/catalogs. When it comes to sharding, Tags provide fine-grained control over tagged machines, allowing administrators to exclude specific machines or apply different sharding values based on the assigned tags. The combination of a custom or fast-track schedule for specific machine groups, along with Zentral's comprehensive reporting and progress metrics, enables accurate monitoring and management of software across the entire fleet.


### Sharding and Autopkg-munki recipes

Anything that an Autopkg recipe exists for can incorporate the Zentral sharding options. This allows you to customize the sharding behavior for "existing" products. For this to work on the munki repository level, you can modify the recipe's override plist file so the value sticks on new versions for "existing" products. By adding a new key called `<key>zentral_monolith</key>`, you can specify the desired sharding behavior. 

In the plist file excerpt provided below, you can see an example of how sharding is added to an Autopkg recipe override file. The `zentral_monolith` key contains a shards dictionary that defines the sharding configuration. The `default` key within the shards dictionary specifies the default number of shards to use (in the example, it's set to 2), while the `modulo` key determines the modulo value for calculating the shard number.

```xml
<key>zentral_monolith</key>
<dict>
	<key>excluded_tags</key>
	<array>
		<string>VIPs</string>
	</array>
	<key>shards</key>
	<dict>
		<key>default</key>
		<integer>2</integer>
		<key>modulo</key>
		<integer>5</integer>
		<key>tags</key>
		<dict>
			<key>Testing</key>
			<integer>5</integer>
		</dict>
	</dict>
</dict>
```


The `tags` dictionary allows administrators to assign separate shards to be applied to machines with determined tags. Additionally, the `excluded_tags` ensures that machines with one of these tags assiged will not receive the software.

To further extend, you can add additional tags to the shards dictionary according to your requirements.