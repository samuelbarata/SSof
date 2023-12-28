#!/bin/python3

import sys, json
import argparse


class bcolors:
    # https://stackoverflow.com/questions/4842424/list-of-ansi-color-escape-sequences
    GREEN =     '\033[92m'
    YELLOW =    '\033[93m'
    RED =       '\033[91m'
    ENDC =      '\033[0m'
    BOLD =      '\033[1m'
    UNDERLINE = '\033[4m'


def match_keys(keys: list, json_object: list) -> bool:
    return set(keys) == set(json_object.keys())


def is_list_of_strings(ll: list) -> bool:
    return all(map(lambda x: isinstance(x, str), ll))


### a flow is a list of tuples (string, int)
def is_flow(flow) -> bool:
    return isinstance(flow, list) and \
        all(map(lambda x: is_instruction(x), flow))


def is_list_of_flows(ll: list) -> bool:
    return all(map(lambda x: is_flow(x), ll))


### an instruction is a tuple (string, int)
def is_instruction(pp: tuple) -> bool:
    return len(pp) == 2 and \
        isinstance(pp[0], str) and \
        isinstance(pp[1], int)


def is_same_flow(flow1, flow2):
    if flow1 == [] and flow2 == []:
        return True
    elif flow1 == [] and flow2 != []:
        return False
    elif flow1 != [] and flow2 == []:
        return False
    else:
        f = flow1[0]
        if f in flow2:
            i = flow2.index(f)
            return is_same_flow(flow1[1:], flow2[:i] + flow2[i+1:])
        else:
            return False


def is_same_list_of_flows(l1, l2):
    if l1 == [] and l2 == []:
        return True
    elif l1 == [] and l2 != []:
        return False
    elif l1 != [] and l2 == []:
        return False
    else:
        f1 = l1[0]
        for f2 in l2:
            if is_same_flow(f1, f2):
                l2.remove(f2)
                return is_same_list_of_flows(l1[1:], l2)


### Check if json object is a valid pattern
def is_pattern(json_obj) -> bool:
    assert match_keys(['vulnerability', 'sources', 'sanitizers', 'sinks', 'implicit'], json_obj), set(json_obj.keys())

    assert isinstance(json_obj['vulnerability'], str), f"vulnerability attribute is of wrong type: {json_obj['vulnerability']}"

    assert isinstance(json_obj['sources'], list), f"sources attribute is of wrong type: {json_obj['sources']}"
    assert is_list_of_strings(json_obj['sources']), f"sources attribute is of wrong type: {json_obj['sources']}"

    assert isinstance(json_obj['sanitizers'], list), f"sanitizers attribute is of wrong type: {json_obj['sanitizers']}"
    assert is_list_of_strings(json_obj['sanitizers']), f"sanitizers attribute is of wrong type: {json_obj['sanitizers']}"

    assert isinstance(json_obj['sinks'], list), f"sinks attribute is of wrong type: {json_obj['sinks']}"
    assert is_list_of_strings(json_obj['sinks']), f"sinks attribute is of wrong type: {json_obj['sinks']}"

    assert isinstance(json_obj['implicit'], str), f"implicit attribute is of wrong type: {json_obj['implicit']}"
    assert json_obj['implicit'] in ["yes", "no"], f"implicit attribute is of wrong type: {json_obj['implicit']}"

    return True


### Check if json object is a valid vulnerability output
def is_vulnerability(json_obj) -> bool:
    assert match_keys(['vulnerability', 'source', 'sink', 'unsanitized_flows', 'sanitized_flows'], json_obj), set(json_obj.keys())

    assert isinstance(json_obj['vulnerability'], str), f"vulnerability attribute is of wrong type: {json_obj['vulnerability']}"

    assert is_instruction(json_obj['source']), f"source attribute is of wrong type: {json_obj['source']}"

    assert is_instruction(json_obj['sink']), f"sink attribute is of wrong type: {json_obj['sink']}"

    assert isinstance(json_obj['unsanitized_flows'], str), f"unsanitized_flows attribute is of wrong type: {json_obj['unsanitized_flows']}"
    assert json_obj['unsanitized_flows'] in ["yes", "no"], f"unsanitized_flows attribute is of wrong type: {json_obj['unsanitized_flows']}"

    assert isinstance(json_obj['sanitized_flows'], list), f"sanitized_flows attribute is of wrong type: {json_obj['sanitized_flows']}"
    assert is_list_of_flows(json_obj['sanitized_flows']), f"sanitized_flows attribute is of wrong type: {json_obj['sanitized_flows']}"

    return True


### 2 vulnerabilities have the same name if they differ in their numbering
##  v == v_3
##  v_1 == v_2
##  v_1_1 == v_1_2
##  v_1_1 != v_1
##  v_1_1 != v_2_1
def is_same_vulnerability_name(name1, name2):
    pos1 = name1.rfind('_')
    pos2 = name2.rfind('_')
    rname1 = name1[:pos1] if pos1 != -1 else name1
    rname2 = name2[:pos2] if pos2 != -1 else name2
    return rname1 == rname2

# assert is_same_vulnerability_name('v', 'v_3') == True
# assert is_same_vulnerability_name('v_1', 'v_2') == True
# assert is_same_vulnerability_name('v_1_1', 'v_1_2') == True
# assert is_same_vulnerability_name('v_1_1', 'v_1') == False
# assert is_same_vulnerability_name('v_1_1', 'v_2_1') == False


### 2 vulnerabilities are the same if they match in everything,
##  regardless of the order of the sanitized_flows
def is_same_vulnerability(v1, v2) -> bool:
    return is_same_vulnerability_name(v1['vulnerability'], v2['vulnerability']) and \
        v1['source'] == v2['source'] and \
        v1['sink'] == v2['sink'] and \
        v1['unsanitized_flows'] == v2['unsanitized_flows'] and \
        is_same_list_of_flows(v1['sanitized_flows'], v2['sanitized_flows'])


def is_vulnerability_in_target(vulnerability, target_list):
    for v in target_list:
        if is_same_vulnerability(vulnerability, v):
            target_list.remove(v)
            return True, target_list

    return False, target_list


### Check if all patterns in filename are valid patterns
def validate_patterns_file(filename: str) -> bool:
    with open(filename, 'r') as f:
        patterns_list = json.loads(f.read())
    assert isinstance(patterns_list, list)

    for json_obj in patterns_list:
        try:
            assert is_pattern(json_obj)
        except Exception as e:
            print(f"\n{bcolors.RED}[-] Incorrect Pattern in file {filename}:\n{e}\n{json_obj}{bcolors.ENDC}\n")
            exit(1)

    print(f"{bcolors.GREEN}[+] All patterns of file {filename} are well defined{bcolors.ENDC}")


### Check if all outputs in filename are valid vulnerability outputs
def validate_output_file(filename: str):
    with open(filename, 'r') as f:
        output_list = json.loads(f.read())
    assert isinstance(output_list, list)

    for json_obj in output_list:
        try:
            assert is_vulnerability(json_obj)
        except Exception as e:
            print(f"\n{bcolors.RED}[-] Incorrect Output in file {filename}:\n{e}\n{json_obj}{bcolors.ENDC}\n")
            exit(1)

    print(f"{bcolors.GREEN}[+] All outputs of file {filename} are well defined{bcolors.ENDC}")


### Check if output in obtained file is the same as in target file
def check_output(obtained, target):
    good = []
    missing = []

    with open(obtained, 'r') as f:
        output_list = json.loads(f.read())

    with open(target, 'r') as f:
        target_list = json.loads(f.read())

    for output in output_list:
        res, target_list = is_vulnerability_in_target(output, target_list)
        if res:
            good.append(output)
        else:
            missing.append(output)

    print(f"\nGOOD FLOWS\n{good}")
    print(f"\n{bcolors.RED}\nMISSING FLOWS\n{missing}{bcolors.ENDC}")
    print(f"\n{bcolors.YELLOW}\nWRONG FLOWS\n{target_list}{bcolors.ENDC}")



parser = argparse.ArgumentParser()
parser.add_argument("--pattern", '-p', help="Validate <pattern> file", default = False)
parser.add_argument("--output", '-o', help="Validate <output> file", default = False)
parser.add_argument("--target", '-t', help="Check <output> vs <target_file>", default = False)

args=parser.parse_args()

print("\n" + "*"*80)
if vars(args)['pattern']:
    validate_patterns_file(vars(args)['pattern'])
if vars(args)['output']:
    validate_output_file(vars(args)['output'])
if vars(args)['output'] and vars(args)['target']:
    validate_output_file(vars(args)['target'])
    check_output(vars(args)['output'], vars(args)['target'])
