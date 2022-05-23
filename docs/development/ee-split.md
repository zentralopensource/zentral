# `ee/` folder split notes

To support our license scheme, some modules and packages were moved to the `ee/` folder found at the top of the repository.

The package references are maintained using the implicit namespace packages from [PEP420](https://peps.python.org/pep-0420/). `__init__.py` files were removed for those packages.

**IMPORTANT:** The Zentral Django apps that are split between the `ee/` and standard folders require an explicit `path` attribute set to the standard folder path. See for example the `server/realms/apps.py` file.
