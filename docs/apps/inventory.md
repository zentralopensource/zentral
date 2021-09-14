# Inventory

The Zentral Inventory app is mandatory in a Zentral deployment. It is used to store all the inventory information.

## Zentral configuration

A `zentral.contrib.inventory` subsection must be present in the `apps` section in [the configuration](/configuration).

### `event_serialization`

**OPTIONAL**

This subsection can be used to change the machine information serialization in the Zentral event metadata. There are two options available:

#### `include_groups`

**OPTIONAL**

This boolean is used to toggle the inclusion of the machine groups in the event metadata. `true` by default.

#### `include_principal_user`

**OPTIONAL**

This boolean is used to toggle the inclusion of the principal user in the event metadata. `true` by default.
