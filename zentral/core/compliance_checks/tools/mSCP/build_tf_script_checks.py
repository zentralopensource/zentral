import argparse
import os
from yaml import load, SafeLoader


TEMPLATE = """resource zentral_munki_script_check "mcs-{section}-{rule}" {{
  name            = "{name}"
  description     = trimspace(<<EODESC
{description}
EODESC
  )
  type            = "{type}"
  source          = trimspace(<<EOSRC
{source}
EOSRC
  )
  expected_result = {expected_result}
  arch_amd64      = {arch_amd64}
  arch_arm64      = {arch_arm64}
  min_os_version  = "{min_os_version}"
  max_os_version  = "{max_os_version}"
}}"""


def iter_rules(guidance_file):
    with open(guidance_file, 'r') as f:
        guidance_data = load(f, Loader=SafeLoader)
        for section in guidance_data.get("profile"):
            yield section["section"], section.get("rules", [])


def get_section_data(repository, section):
    filepath = os.path.join(repository, "sections", f"{section}.yaml")
    with open(filepath, "r") as f:
        return load(f, Loader=SafeLoader)


def get_rule_data(repository, rule):
    for dirpath, _, filenames in os.walk(os.path.join(repository, "rules")):
        for filename in filenames:
            if filename.startswith(rule):
                filepath = os.path.join(
                    dirpath,
                    filename
                )
                with open(filepath, "r") as f:
                    return load(f, Loader=SafeLoader)
    input(f"Unknown rule: {rule}!")


def get_custom_dir(repository, custom_dir):
    if custom_dir:
        return custom_dir
    else:
        return os.path.join(repository, "custom")


def get_rule_custom_data(repository, custom_dir, rule):
    custom_dir = get_custom_dir(repository, custom_dir)
    filepath = os.path.join(custom_dir, "rules", f"{rule}.yaml")
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return load(f, Loader=SafeLoader)


def escape_terraform_string(s, double_quotes=True):
    s = s.replace("${", "$${").replace("%{", "%%{")
    if double_quotes:
        s = s.replace('"', '\\"')
    return s


def set_odv(s, odv):
    return s.replace("$ODV", str(odv))


def get_script_check_data(
    section_data,
    rule_data,
    rule_custom_data,
    default_odv_source
):
    result = rule_data.get("result")
    if not result:
        print("  🔥 no script result found in rule definition")
        return

    title = rule_data["title"]
    discussion = rule_data["discussion"].strip()
    source = rule_data["check"].strip()

    try:
        base64_result = str(result["base64"])
    except KeyError:
        base64_result = ""
    try:
        integer_result = str(result["integer"])
    except KeyError:
        integer_result = ""
    try:
        string_result = str(result["string"])
    except KeyError:
        string_result = ""
    # $ODV
    if any(
        "$ODV" in s
        for s in (title, discussion, source, base64_result, integer_result, string_result)
    ):
        odv = None
        try:
            odv = rule_custom_data["odv"]["custom"]
        except (AttributeError, KeyError, TypeError):
            try:
                odv = rule_data["odv"][default_odv_source]
            except KeyError:
                input(f"Could not find $ODV value for '{default_odv_source}'")
            print(f"  ✦ Use {default_odv_source} $ODV: '{odv}'")
        else:
            print(f"  ✦ Found custom $ODV: '{odv}'")
        if odv is not None:
            title = set_odv(title, odv)
            discussion = set_odv(discussion, odv)
            source = set_odv(source, odv)
            base64_result = set_odv(base64_result, odv)
            integer_result = set_odv(integer_result, odv)
            string_result = set_odv(string_result, odv)
        else:
            print("  🔥 Missing $ODV!")
            return
    sca = {
        "name": f'[mSCP] - {section_data["name"]} - {title}',
        "description": discussion,
        "source": escape_terraform_string(source, double_quotes=False),
    }
    # type
    raw_expected_result = False
    if "string" in result:
        sc_type = "ZSH_STR"
        sc_expected_result = escape_terraform_string(string_result)
    elif "integer" in result:
        sc_type = "ZSH_INT"
        sc_expected_result = escape_terraform_string(integer_result)
    elif "boolean" in result:
        sc_type = "ZSH_BOOL"
        sc_expected_result = str(rule_data["result"]["boolean"])
    elif "base64" in result:
        sc_type = "ZSH_STR"
        raw_expected_result = True
        tf_expected_result = escape_terraform_string(base64_result)
        sc_expected_result = f'base64encode("{tf_expected_result}\\n")'
    else:
        print("  🔥 Unknown result type:", result)
        return
    if not raw_expected_result:
        sc_expected_result = f'"{sc_expected_result}"'
    tags = rule_data.get("tags", [])
    # arch
    sc_arch_amd64 = sc_arch_arm64 = "true"
    if "i386" in tags:
        sc_arch_arm64 = "false"
    elif "arm64" in tags:
        sc_arch_amd64 = "false"
    sca.update({
        "type": sc_type,
        "arch_amd64": sc_arch_amd64,
        "arch_arm64": sc_arch_arm64,
        "expected_result": sc_expected_result,
    })
    # min/max OS version
    if "macOS" not in rule_data or not rule_data.get("macOS"):
        print("  🔥 no macOS versions found")
        return sca
    min_os_ver_elm = min([int(i) for i in v.split(".")]
                         for v in rule_data["macOS"])
    min_os_version = ".".join(str(i) for i in min_os_ver_elm)
    max_os_version = str(min_os_ver_elm[0] + 1)
    sca.update({
        "min_os_version": min_os_version,
        "max_os_version": max_os_version,
    })
    return sca


def generate_terraform_resources(
    guidance_file,
    repository,
    output_file,
    custom_dir,
    min_os_version,
    max_os_version,
    default_odv_source,
):
    with open(output_file, "w") as f:
        for section, rules in iter_rules(guidance_file):
            section_data = get_section_data(repository, section)
            print("Section", section_data["name"])
            for rule in rules:
                if rule.startswith("supplemental_"):
                    print("  ❌ Supplemental rule", rule, "skipped!!!")
                    continue
                rule_data = get_rule_data(repository, rule)
                rule_custom_data = get_rule_custom_data(repository,
                                                        custom_dir,
                                                        rule)
                print("  Rule", rule_data["title"])
                sc_data = get_script_check_data(
                    section_data,
                    rule_data,
                    rule_custom_data,
                    default_odv_source,
                )
                if not sc_data:
                    print("  ❌ rule", rule, "skipped!!!")
                    continue
                if min_os_version:
                    sc_data["min_os_version"] = min_os_version
                if max_os_version:
                    sc_data["max_os_version"] = max_os_version
                if "min_os_version" not in sc_data or "max_os_version" not in sc_data:
                    print("  ❌ Missing min OS version or max OS version", rule, "skipped!!!")
                    continue
                f.write(
                    TEMPLATE.format(
                        section=section,
                        rule=rule,
                        **sc_data
                    )
                )
                f.write("\n\n")


def main():
    parser = argparse.ArgumentParser(
        prog='build_tf_script_checks.py',
        description='Takes a mSCP guideline YAML file '
                    'and build the Terraform Munki script checks resources.',
    )
    parser.add_argument(
        "guidance_file",
        help="Path of the mSCP guidance file, usually in the `build/guidances` "
             "subfolder of the cloned mSCP repository"
    )
    parser.add_argument(
        "repository",
        help="Path of the mSCP cloned repository"
    )
    parser.add_argument(
        "output_file",
        help="Path of the Terraform output file"
    )
    parser.add_argument("--min-os-version", default="")
    parser.add_argument("--max-os-version", default="")
    parser.add_argument(
        "--custom-dir",
        help="Path of the folder containing the custom ODVs. "
             "Defaults to the `custom` subfolder of the cloned mSCP repository"
    )
    parser.add_argument(
        "--default-odv-source",
        default="recommended",
        help="Key of the default ODV values to choose in the rule definition file, "
             "if no custom value is found. Defaults to `recommended`"
    )
    args = parser.parse_args()
    generate_terraform_resources(
        args.guidance_file,
        args.repository,
        args.output_file,
        args.custom_dir,
        args.min_os_version,
        args.max_os_version,
        args.default_odv_source,
    )


if __name__ == "__main__":
    main()
