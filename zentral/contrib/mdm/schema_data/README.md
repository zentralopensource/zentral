# Apple MDM schema data

Some of the folders and files from the [Apple device management GitHub repository](https://github.com/apple/device-management) are vendored in this folder. They are used to validate inputs and automate forms.

To update them when there is a new release, use the [`update.sh`](./update.sh) script. The current git reference is written to [`reference.txt`](./reference.txt).

## Declarations

The definitions of the DDM declarations are used to validate the *activations* → *configurations* → *assets* references.

## SkipKeys

The ADE profile skipkeys options are loaded from the [`skipkeys.yaml`](./other/skipkeys.yaml) file.
