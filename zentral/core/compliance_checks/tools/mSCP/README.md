# mSCP Terraform tool

This script takes a [macOS Security Compliance](https://github.com/usnistgov/macos_security) benchmark with ODVs and outputs a [Terraform](https://www.terraform.io/) file containing the Zentral [Munki script check resources](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/munki_script_check). The Terraform file can be applied to a Zentral instance.

This is the recommended way to implement mSCP checks with Zentral.
