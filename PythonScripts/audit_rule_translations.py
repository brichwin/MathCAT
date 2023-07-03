#!/usr/bin/env python3
"""Audit rule translations."""
# pylint: disable=line-too-long
#
# This script compares the English and translated rule files and reports on any differences.
# It is a response to [Tool to compare translations to make sure they are up-to-date #69](https://github.com/NSoiffer/MathCAT/issues/69)
#
# Functions:
#   - Parse command line arguments (see below for usage)
#   - Read the English and translated rule files
#   - Compare the files and report on any differences
#     -- Report on any duplicate rules in the English or translated files (and then abort)
#     -- Report on rules that have key values needing translation
#     -- Report on rules that are in the translated file but are not in the English file
#     -- Report on rules that are in the English file but are not in the translated file
#     -- Report on rules that are in both files but have differents beyond translation keys
#   - Optionally, create a new version of the translated file with comments where translation is needed
#     -- The original translation file is backup up with a ".bak" extension and numbered if necessary
#     -- Discard any previous "# [AUDIT]" comments in the translated file
#     -- Any comments added have the text "# [AUDIT]" in them to make finding them (and removing them) easier
#

# ----

#
# usage: audit_rule_translations.py [-h] [--mode {warnings,new_version}]
#                                  [--unicode {true,false,auto}]
#                                  english_rules translated_rules
#
# Audit a translated rules file against its English version.
#
# positional arguments:
#   english_rules         The English version of the rules YAML file.
#   translated_rules      The translated version of the rules YAML file.
#
# options:
#   -h, --help            show this help message and exit
#   --mode {warnings,new_version}
#                        In 'warnings' mode (default), differences between
#                        files are listed as warnings. In 'new_version' mode, a
#                        new version of the translated file is created with
#                        comments where translation is needed.
#   --unicode {true,false,auto}
#                        Use 'true' to force handling the file as a unicode
#                        definitions yaml file. Use 'false' to force handling
#                        the file as a non-unicode definitions yaml file. Use
#                        'auto' (default) mode to automatically detect if the file is a
#                        unicode definitions yaml file by inspecting the
#                        filename for 'unicode'.

# ----

#
# Assumptions:
#   - The English file is the "source of truth" for the rule structure
#   - The document start marker ("---") is optional
#   - The English file contains only one yaml document
#   - Comments that occur immediately after the document start marker ("---") are document level comments
#   - Comments occuring after a blank line after the document start marker ("---") and any document level comments belong to the first rule
#   - Comments that occur immediately after a rule are rule level comments for the next rule
#   - Existing audit comments in the translated file are discarded and new ones if needed are inserted.
#   - If audit comments already exist in the translated file, they are discarded and new ones are inserted.
#   - If audit comments already exist in the translated file, the translated file is always rewritten.
#   - If no audit comments already exist in the translated file, the translated file is only rewritten if there are new audit comments to insert.
#      -- The second pass writes to a temp file and then if there are any changes, it:
#         --- backs up the original translated yaml file
#         --- renames the temp file to the original file name
#      -- otherwise, the temp file is deleted
#   - The English file contains a sequence of rules or unicode chars at the root level
#   - The non-unicode rule hash keys always contain the "name" and "tag" keys in that order
#   - A non-unicode rule is uniquely identified by its "name" and "tag" keys (that combination is the rule's key and it does not repeat)
#   - The presence of "unicode" in the file name indicates that the file is a sequence of unicode char names
#   - Unicode files are always a sequence of dictionaries with a single key/value pair
#   - We don't need to worry about tab chars vs. spaces in the yaml files for computing indentation levels
#   - Differences in the comments are not significant and do not need to be reported
#   - Exact line spacing is not important and does not need to be preserved although attempts were made to preserve it
#
# ----
#
# Dev notes:
#   - Attempted to use ruamel.yaml for parsing and writing the yaml files
#     to take advantage of it's claim of preserving comments and allowing
#     round-trip processing -> dumping, but I could not figure out how to
#     read comments before / after associated to rules to process them. Also:
#       -- inserting / adding rules to the translation yaml dict appeared to scramble
#          the order of the comments.
#       -- Despite adding ```yaml.allow_unicode = True``` the round_trip_dumper would
#          throw execptions for certain unicode chars in the translation files!
#       -- ruamel.yaml is still beta and the api is listed as not stable so I gave up on it.
#   - Python style used is "Black"

import argparse
import io
import os
# import pprint
import re
import sys
import tempfile
import yaml

# Set encoding to utf-8 for stdin and stdout (required on Windows to output unicode chars)
sys.stdin.reconfigure(encoding='utf-8')
sys.stdout.reconfigure(encoding='utf-8')

def line_is_blank(line: str) -> bool:
    """Check if a line is blank."""
    return not bool(line and line.replace("\xa0", " ").strip())


def line_is_start_of_document(line: str) -> bool:
    """Check if a line is the start of a document."""
    return bool(re.match(r"^---", line.rstrip("\r\n")))


def line_is_a_translation_audit_comment(line: str) -> bool:
    """Check if a line is an inserted audit comment."""
    # Audit comments are inserted as a full-line comment with the text "# [AUDIT]"
    return bool(re.match(r"^\s*#\s*\[AUDIT\]", line))


def line_is_a_normal_comment(line: str) -> bool:
    """Check if a line starts with a comment."""
    return bool(re.match(r"^\s*#", line)) and not line_is_a_translation_audit_comment(
        line
    )

def write_any_leading_blank_lines(out_file, buffered_lines):
    """Write any blank lines at the head of a list of buffered lines."""
    while len(buffered_lines) > 0 and line_is_blank(buffered_lines[0]):
        out_file.write(buffered_lines[0])
        del buffered_lines[0]

def get_key_from_line(line):
    """Get a rule key from a line."""
    match = re.match(r'^\s*-\s*"([^"]*)"\s*:', line)
    if match:
        return match.group(1)
    match = re.search(r"^\s*-\s+'(.+?)'\s*:", line)
    if match:
        return match.group(1)
    return None


def format_rule_key_from_dict(rule: dict) -> str:
    """Format a rule key from a dictionary."""
    tag = (
        "[" + ", ".join(sorted(rule["tag"])) + "]"
        if isinstance(rule["tag"], list)
        else rule["tag"]
    )
    rule_key = rule["name"] + ":" + tag
    return rule_key

def format_rule_key_for_display(rule_key: str) -> str:
    """Format a rule key for display by placing it in quotes and also
      displaying the unicode char hex value if the key is one char."""
    if len(rule_key) == 1:
        return f"'{rule_key}' (Unicode char: \\u{format(ord(rule_key),'04x')})"
    return f"'{rule_key}'"

def get_rule_key_from_buffered_lines(lines: []) -> str:
    """Get a rule key from a list of buffered lines."""
    rule_key = None
    from_buffer = yaml.safe_load("".join(lines))

    if len(from_buffer) == 1:
        rule = from_buffer[0]
        if "name" in rule and "tag" in rule:
            tag = (
                "[" + ", ".join(sorted(rule["tag"])) + "]"
                if isinstance(rule["tag"], list)
                else rule["tag"]
            )
            rule_key = rule["name"] + ":" + tag

    return rule_key


def count_untranslated_keys_in_dict(dictionary: dict) -> int:
    """Recursively count untranslated keys in a dictionary."""
    count = 0
    for key, value in dictionary.items():
        if key in ["t", "ot", "oc"]:
            count += 1
        if isinstance(value, dict):
            count += count_untranslated_keys_in_dict(value)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    count += count_untranslated_keys_in_dict(item)
    return count


ignored_keys = {"t", "T", "oc", "OC", "CT", "ct"}

def lists_are_the_same(list1: list, list2: list, path) -> tuple[list, bool]:
    """Recursively compare two lists."""
    warning_msgs = []
    if len(list1) != len(list2):
        warning_msgs.append("Lists don't have the same length at path: " + path)
        return warning_msgs, False

    for index, (item1, item2) in enumerate(zip(list1, list2)):
        if isinstance(item1, dict) and isinstance(item2, dict):
            warnings, match = dictionaries_are_the_same_besides_translations(item1, item2, f"{path}[{index}]" )
            warning_msgs.extend(warnings)
            if not match:
                return warning_msgs, False
        elif item1 != item2:
            warning_msgs.append(f"List item values don't match at path: {path}[{index}]:")
            warning_msgs.append(f"  1: {item1}")
            warning_msgs.append(f"  2: {item2}")
            return warning_msgs, False

    return warning_msgs, True


def dictionaries_are_the_same_besides_translations(
    dict1: dict, dict2: dict, path: str
) -> tuple[list, bool]:
    """Recursively compare two dictionaries while ignoring text keys."""
    warning_msgs = []
    if set(dict1.keys()) - ignored_keys != set(dict2.keys()) - ignored_keys:
        warning_msgs.append(f"Dictionaries don't have the same keys at path: {path}")
        if len(set(dict1.keys() - ignored_keys) - set(dict2.keys() - ignored_keys)) > 0:
            warning_msgs.append(
                f"Keys in first dictionary that are not in second dictionary: {set(dict1.keys() - ignored_keys) - set(dict2.keys() - ignored_keys)}"
            )
        if len(set(dict2.keys() - ignored_keys) - set(dict1.keys() - ignored_keys)) > 0:
            warning_msgs.append(
                f"Keys in second dictionary that are not in first dictionary: {set(dict2.keys() - ignored_keys) - set(dict1.keys() - ignored_keys)}"
            )
        return warning_msgs, False

    for k in dict1.keys():
        if k in ignored_keys:
            continue
        if isinstance(dict1[k], dict):
            warnings, match = dictionaries_are_the_same_besides_translations(
                dict1[k], dict2[k], f"{path}['{k}']"
            )
            warning_msgs.extend(warnings)
            if not match:
                return warning_msgs, False
        elif isinstance(dict1[k], list):
            if not isinstance(dict2[k], list) or len(dict1[k]) != len(dict2[k]):
                warning_msgs.append(f"lists don't match at path: {path}['{k}']")
                return warning_msgs, False
            warnings, match = lists_are_the_same(dict1[k], dict2[k], f"{path}['{k}']")
            warning_msgs.extend(warnings)
            if not match:
                return warning_msgs, False
        elif dict1[k] != dict2[k]:
            warning_msgs.append(f"Values for key: {k} don't match at path: {path}['{k}']:")
            warning_msgs.append(f"  1: {dict1[k]}")
            warning_msgs.append(f"  2: {dict2[k]}")
            return warning_msgs, False

    return warning_msgs, True


def create_temp_file_name(original_file: str) -> str:
    """Create a temporary file with the same base name as the original file."""
    base_name = os.path.basename(original_file)
    dir_name = os.path.dirname(original_file)
    temp_file = tempfile.NamedTemporaryFile(
        prefix=base_name, dir=dir_name, delete=False
    )
    return temp_file.name


def backup_file(filename):
    """Backup a file by renaming it with a .bak extension."""
    # Start from .bak
    backup_filename = filename + ".bak"

    # If the backup file already exists, append a number
    counter = 2
    while os.path.exists(backup_filename):
        backup_filename = f"{filename}-{counter}.bak"
        counter += 1

    # Rename the file
    os.rename(filename, backup_filename)

    return backup_filename


def grab_missing_rule_lines(
    missing_rule_key: str, from_file_name: str, is_a_unicode_file: bool
) -> list:
    """Grab the lines for a rule from the English file."""
    inf = io.open(from_file_name, "r", encoding="utf-8")

    # use Note to indicate that the root sequence's indention level is not known yet
    indentation = None
    past_start_of_document = False

    buffered_lines = []

    last_buffered_non_blank_non_comment_line = None
    current_rule_key = None
    found_name_key = False

    for line in inf:
        # Don't buffer the document start and assumed "document comments"
        if not past_start_of_document:
            if not line_is_a_normal_comment(line) and not line_is_start_of_document(
                line
            ):
                past_start_of_document = True

        if past_start_of_document and not line_is_a_translation_audit_comment(line):
            stripped = line.lstrip()
            if stripped.startswith("- "):
                if indentation is None:
                    # Set indentation level of root sequence
                    indentation = len(line) - len(stripped)

                # Detect new item in the root sequence
                if len(line) - len(stripped) == indentation:
                    if missing_rule_key == current_rule_key:
                        # We have the rule we're looking for because current_rule_key
                        # is previous rule's key. We likely have comments and/or blank
                        # lines to dump that are for the next rule. We can handle that
                        # at the loop's end
                        break  # exit loop

                    # Previous rule ended (if any)
                    # Dump buffered lines up to and including the last non-blank, non-comment line
                    del buffered_lines[:last_buffered_non_blank_non_comment_line]
                    last_buffered_non_blank_non_comment_line = None

                    current_rule_key = None
                    found_name_key = False

            buffered_lines.append(line)
            if not line_is_blank(line) and not line_is_a_normal_comment(line):
                last_buffered_non_blank_non_comment_line = len(buffered_lines)

            if indentation is not None and current_rule_key is None:
                if is_a_unicode_file:
                    current_rule_key = get_key_from_line(line)
                if re.match(r"^\s*-*\s*name:\s*\S+", line):
                    found_name_key = True
                if found_name_key and re.match(r"^\s*tag:\s*\S+", line):
                    current_rule_key = get_rule_key_from_buffered_lines(buffered_lines)

    if len(buffered_lines) > 0 and missing_rule_key == current_rule_key:
        # We have the rule we're looking for because current_rule_key is previous rule's key
        # We likely have comments and/or blank lines to dump that are for the next rule
        del buffered_lines[last_buffered_non_blank_non_comment_line:]
    else:
        buffered_lines = []

    return buffered_lines


def main():
    """Audit rule translations."""
    parser = argparse.ArgumentParser(
        description="Audit a translated rules file against its English version."
    )
    parser.add_argument(
        "english_rules", help="The English version of the rules YAML file."
    )
    parser.add_argument(
        "translated_rules", help="The translated version of the rules YAML file."
    )
    parser.add_argument(
        "--mode",
        choices=["warnings", "new_version"],
        default="warnings",
        help="In 'warnings' mode (default), differences between files are \
            listed as warnings. In 'new_version' mode, a new version of the \
            translated file is created with comments where translation is needed.",
    )
    parser.add_argument(
        "--unicode",
        choices=["true", "false", "auto"],
        default="auto",
        help="Use 'true' to force handling the file as a unicode definitions yaml file. Use 'false' to force handling the file as a non-unicode definitions yaml file. Use 'auto' (default) mode to automatically detect if the file is a unicode definitions yaml file by inspecting the filename for 'unicode'.",
    )
    args = parser.parse_args()

    # Load the YAML files
    english_file = io.open(args.english_rules, "r", encoding="utf-8")
    translated_file = io.open(args.translated_rules, "r", encoding="utf-8")

    english_rules = yaml.safe_load(english_file.read().replace("\t", " "))
    translated_rules = yaml.safe_load(translated_file.read().replace("\t", " "))

    english_file.close()
    translated_file.close()

    # Check if the file is a unicode definitions yaml file
    unicode_yaml_file = False
    if args.unicode == "true":
        unicode_yaml_file = True
    elif args.unicode == "false":
        unicode_yaml_file = False
    elif (re.search(r"unicode", args.translated_rules, re.IGNORECASE)) is not None:
        unicode_yaml_file = True

    print(
        f"\nProcessing {len(english_rules)} items in {'Unicode' if unicode_yaml_file else 'Non-Unicode'} mode.\n"
    )

    # Store rules as dictionaries for easy lookup
    english_dict = {}
    english_dict_occurs_after = {}

    previous_rule_key = None
    duplicate_keys_in_english_file = False
    duplicate_keys_in_translated_file = False

    for rule in english_rules:
        if unicode_yaml_file is True:
            # TODO: Handle exception where rule is not a dictionary with one key
            rule_key = list(rule.keys())[0]
            if rule_key in english_dict:
                print(f"Warning: Duplicate key {format_rule_key_for_display(rule_key)} in english file.")
                duplicate_keys_in_english_file = True
            else:
                english_dict[rule_key] = rule
                english_dict_occurs_after[rule_key] = previous_rule_key
            previous_rule_key = rule_key
        elif unicode_yaml_file is False and "name" in rule and "tag" in rule:
            tag = (
                "[" + ", ".join(sorted(rule["tag"])) + "]"
                if isinstance(rule["tag"], list)
                else rule["tag"]
            )
            rule_key = rule["name"] + ":" + tag
            if rule_key in english_dict:
                print(f"Warning: Duplicate key {format_rule_key_for_display(rule_key)} in english file.")
                duplicate_keys_in_english_file = True
            else:
                english_dict[rule_key] = rule
                english_dict_occurs_after[rule_key] = previous_rule_key
            previous_rule_key = rule_key

    translated_dict = {}
    for rule in translated_rules:
        if unicode_yaml_file is True:
            # TODO: Handle exception where rule is not a dictionary with one key
            rule_key = list(rule.keys())[0]
            if rule_key in translated_dict:
                print(f"Warning: Duplicate key {format_rule_key_for_display(rule_key)} in translated file.")
                duplicate_keys_in_translated_file = True
            else:
                translated_dict[rule_key] = rule
        elif unicode_yaml_file is False and "name" in rule and "tag" in rule:
            tag = (
                "[" + ", ".join(sorted(rule["tag"])) + "]"
                if isinstance(rule["tag"], list)
                else rule["tag"]
            )
            rule_key = rule["name"] + ":" + tag
            if rule_key in translated_dict:
                print(f"Warning: Duplicate key {format_rule_key_for_display(rule_key)} in translated file.")
                duplicate_keys_in_translated_file = True
            else:
                translated_dict[rule_key] = rule

    rules_with_untranslated_keys = {}
    rule_missing_in_translated_file_after = {}
    rules_extra_in_translated_file = {}
    rules_with_differences = {}

    # Report untranslated rules
    for rule_key, rule in translated_dict.items():
        if isinstance(rule, dict):
            count_of_untranslated_keys = count_untranslated_keys_in_dict(rule)
            if count_of_untranslated_keys > 0:
                rules_with_untranslated_keys[rule_key] = count_of_untranslated_keys
                print(
                    f"Rule {format_rule_key_for_display(rule_key)} still contains {count_of_untranslated_keys} key(s) needing translating."
                )

    # Report missing rules
    for rule_key in english_dict:
        if rule_key not in translated_dict:
            rule_missing_in_translated_file_after[
                english_dict_occurs_after[rule_key]
            ] = rule_key
            print(f"Rule {format_rule_key_for_display(rule_key)} is missing in the translated file.")

    # Report extra rules
    for rule_key in translated_dict:
        if rule_key not in english_dict:
            rules_extra_in_translated_file[rule_key] = True
            print(
                f"Warning: Rule {format_rule_key_for_display(rule_key)} in translated file is not in the English file."
            )

    # Compare non-translation fields in rules contained in both files
    for rule_key, english_rule in english_dict.items():
        if rule_key in translated_dict:
            # print(f"Comparing rule {format_rule_key_for_display(rule_key)}.")
            # pprint.pprint(english_rule)
            # print("vs.")
            # pprint.pprint(translated_dict[rule_key])
            warnings, same_flag = dictionaries_are_the_same_besides_translations(
                english_rule, translated_dict[rule_key], rule_key
            )
            if not same_flag:
                rules_with_differences[rule_key] = True
                print(
                    f"Warning: Rule {format_rule_key_for_display(rule_key)} contains differences other than ones in t, T, OC, oc, CT, ct keys:"
                )
                for warning in warnings:
                    print(f"  - {warning}")

    if duplicate_keys_in_translated_file or duplicate_keys_in_english_file:
        print(
            "\nStopping: Duplicate keys in the English or translated file may cause incorrect results."
        )
        exit(1)

    if args.mode == "new_version":
        # Create a new version of the translated file with comments where translation is needed
        # Assumes that any full line comments that occur after first blank line & before the first rule belong to that rule

        print(
            "\nCreating new version of translated file with comments where translation is needed."
        )

        # TODO: remove this debug code
        print("Missing rules:")
        for rule_key, value in rule_missing_in_translated_file_after.items():
            print(f"  {value} is missing after {rule_key}")

        print("")

        temp_file_name = create_temp_file_name(args.translated_rules)

        in_file = io.open(args.translated_rules, "r", encoding="utf-8")
        out_file = io.open(temp_file_name, "w", encoding="utf-8")

        # use Note to indicate that the root sequence's indention level is not known yet
        indentation = None

        previous_rule_key = None
        past_start_of_document = False

        buffered_lines = []
        contains_audit_comments = False
        last_buffered_non_blank_non_comment_line = None
        current_rule_key = None
        found_name_key = False
        buffered_line_containing_name_key = None

        count_of_needs_translation_comments = 0
        count_of_new_rule_comments = 0
        count_of_contains_differences_comments = 0
        count_of_rule_not_in_english_file_comments = 0

        for line in in_file:
            if line_is_a_translation_audit_comment(line):
                contains_audit_comments = True
                continue
            if not past_start_of_document:
                if not line_is_a_normal_comment(line) and not line_is_start_of_document(
                    line
                ):
                    past_start_of_document = True
                    out_file.writelines(buffered_lines)
                    buffered_lines = []
                else:
                    buffered_lines.append(line)

            if past_start_of_document and not line_is_a_translation_audit_comment(line):
                stripped = line.lstrip()
                if stripped.startswith("- "):
                    if indentation is None:
                        # Set indentation level of root sequence
                        indentation = len(line) - len(stripped)

                    # Detect new item in the root sequence
                    if len(line) - len(stripped) == indentation:
                        if (
                            len(buffered_lines) > 0
                            and last_buffered_non_blank_non_comment_line is not None
                        ):
                            # Write out any buffered lines that belong to the previous rule
                            out_file.write(
                                "".join(
                                    buffered_lines[
                                        :last_buffered_non_blank_non_comment_line
                                    ]
                                )
                            )
                            del buffered_lines[
                                :last_buffered_non_blank_non_comment_line
                            ]
                            last_buffered_non_blank_non_comment_line = None

                        while (
                            # current_rule_key is still the "previous" rule key
                            current_rule_key
                            in rule_missing_in_translated_file_after
                        ):
                            missing_rule_key = rule_missing_in_translated_file_after[
                                current_rule_key
                            ]
                            missing_lines = grab_missing_rule_lines(
                                missing_rule_key, args.english_rules, unicode_yaml_file
                            )
                            comment_added = False
                            for missing_line in missing_lines:
                                if not comment_added and (unicode_yaml_file is True or re.match(r"^\s*-\s*name:", missing_line)):
                                    if current_rule_key is None:
                                        out_file.write("\n")
                                    out_file.write(
                                        f'{" " * indentation}# [AUDIT] NEW RULE \'{missing_rule_key}\' THAT NEEDS TRANSLATION\n'
                                    )
                                    count_of_new_rule_comments += 1
                                    comment_added = True
                                out_file.write(missing_line)
                            del rule_missing_in_translated_file_after[current_rule_key]
                            current_rule_key = missing_rule_key

                        current_rule_key = None
                        found_name_key = False
                        buffered_line_containing_name_key = None

                buffered_lines.append(line)
                if not line_is_blank(line) and not line_is_a_normal_comment(line):
                    last_buffered_non_blank_non_comment_line = len(buffered_lines)

                if indentation is not None and current_rule_key is None:
                    just_found_rule_key = False
                    if unicode_yaml_file is True:
                        current_rule_key = get_key_from_line(line)
                        just_found_rule_key = True
                    elif re.match(r"^\s*-*\s*name:\s*\S+", line):
                        found_name_key = True
                        buffered_line_containing_name_key = len(buffered_lines)
                    if found_name_key and re.match(r"^\s*tag:\s*\S+", line):
                        current_rule_key = get_rule_key_from_buffered_lines(
                            buffered_lines
                        )
                        just_found_rule_key = True
                    if just_found_rule_key:
                        # Write out buffered lines before line with name key
                        if buffered_line_containing_name_key is not None and buffered_line_containing_name_key > 1:
                            out_file.write(
                                "".join(
                                    buffered_lines[
                                        : buffered_line_containing_name_key - 1
                                    ]
                                )
                            )
                            del buffered_lines[: buffered_line_containing_name_key - 1]
                        buffered_line_containing_name_key = None

                        if current_rule_key in rules_with_untranslated_keys:
                            write_any_leading_blank_lines(out_file, buffered_lines)
                            out_file.write(
                                f'{" "*indentation}# [AUDIT] RULE \'{current_rule_key}\' NEEDS TRANSLATION OF {rules_with_untranslated_keys[current_rule_key]} KEYS\n'
                            )
                            count_of_needs_translation_comments += 1
                        if current_rule_key in rules_extra_in_translated_file:
                            write_any_leading_blank_lines(out_file, buffered_lines)
                            out_file.write(
                                f'{" "*indentation}# [AUDIT] RULE \'{current_rule_key}\' RULE NOT IN ENGLISH FILE\n'
                            )
                            count_of_rule_not_in_english_file_comments += 1
                        if current_rule_key in rules_with_differences:
                            write_any_leading_blank_lines(out_file, buffered_lines)
                            out_file.write(
                                f'{" "*indentation}# [AUDIT] RULE \'{current_rule_key}\' HAS DIFFERENCES OTHER THAN TRANSLATION\n'
                            )
                            count_of_contains_differences_comments += 1

        # Hit EOF, so check if any remaining missing rules exist
        # First write out any buffered lines that belong to the previous rule
        if current_rule_key in rule_missing_in_translated_file_after:
            # finish writing out previous rule
            out_file.write(
                "".join(buffered_lines[:last_buffered_non_blank_non_comment_line])
            )
            del buffered_lines[:last_buffered_non_blank_non_comment_line]
            last_buffered_non_blank_non_comment_line = None

            while (
                # current_rule_key is still the "previous" rule key
                current_rule_key
                in rule_missing_in_translated_file_after
            ):
                missing_rule_key = rule_missing_in_translated_file_after[
                    current_rule_key
                ]
                missing_lines = grab_missing_rule_lines(
                    missing_rule_key, args.english_rules, unicode_yaml_file
                )
                comment_added = False
                for missing_line in missing_lines:
                    if not comment_added and (unicode_yaml_file is True or re.match(r"^\s*-\s*name:", missing_line)):
                        if current_rule_key is None:
                            out_file.write("\n")
                        out_file.write(
                            f'{" " * indentation}# [AUDIT] NEW RULE \'{missing_rule_key}\' THAT NEEDS TRANSLATION\n'
                        )
                        comment_added = True
                        count_of_new_rule_comments += 1
                    out_file.write(missing_line)
                del rule_missing_in_translated_file_after[current_rule_key]
                current_rule_key = missing_rule_key

        # Write out any remaining buffered lines
        if len(buffered_lines) > 0:
            out_file.writelines(buffered_lines)

        in_file.close()
        out_file.close()

        total_new_comments_added = (
            count_of_contains_differences_comments
            + count_of_rule_not_in_english_file_comments
            + count_of_needs_translation_comments
            + count_of_new_rule_comments
        )

        if contains_audit_comments or total_new_comments_added > 0:
            backup_filename = backup_file(args.translated_rules)
            os.rename(temp_file_name, args.translated_rules)

            print(
                f"New version of {args.translated_rules} created. Original backed up to {backup_filename}."
            )
            if count_of_new_rule_comments > 0:
                print(
                    f"  {count_of_new_rule_comments} new rule(s) that need translation."
                )
            if count_of_needs_translation_comments > 0:
                print(
                    f"  {count_of_needs_translation_comments} rule(s) that need translation of keys."
                )
            if count_of_rule_not_in_english_file_comments > 0:
                print(
                    f"  {count_of_rule_not_in_english_file_comments} rule(s) not in English file."
                )
            if count_of_contains_differences_comments > 0:
                print(
                    f"  {count_of_contains_differences_comments} rule(s) with differences other than translation."
                )
        else:
            print(f"No changes needed to {args.translated_rules}.")
            if os.path.exists(
                temp_file_name and temp_file_name != args.translated_rules
            ):
                os.remove(temp_file_name)


if __name__ == "__main__":
    main()
