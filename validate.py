#!/bin/python3

import json
import argparse

class Flow:
    def __init__(self, sanitizers):
        self.sanitizers = sanitizers

    def __repr__(self):
        return f"Flow(sanitizers={self.sanitizers})"

    def __eq__(self, other):
        if not isinstance(other, Flow):
            return False
        return self.sanitizers == other.sanitizers

class Vulnerability:
    def __init__(self, vulnerability, source, sink:str, unsanitized_flows, sanitized_flows):
        vuln_name = vulnerability.split('_')[:-1]
        self.vulnerability = ''.join(vuln_name) if vuln_name else vulnerability
        self.source = source
        self.sink = sink
        self.unsanitized_flows = unsanitized_flows
        self.sanitized_flows = sanitized_flows

    def __repr__(self):
        return (
            f"Vulnerability("
            f"vulnerability={self.vulnerability}, "
            f"source={self.source}, "
            f"sink={self.sink}, "
            f"unsanitized_flows={self.unsanitized_flows}, "
            f"sanitized_flows={self.sanitized_flows})"
        )

    def __eq__(self, other):
        if isinstance(other, Vulnerability):
            other: Vulnerability
            return (
                self.vulnerability == other.vulnerability and
                self.source == other.source and
                self.sink == other.sink and
                self.unsanitized_flows == other.unsanitized_flows and
                self.sanitized_flows == other.sanitized_flows
            )
        return False

def parse_flow(flow_data):
    if flow_data == "none":
        return None
    return Flow([tuple(item) for item in flow_data])

def parse_vulnerability(vulnerability_data):
    vulnerability = vulnerability_data["vulnerability"]
    source = tuple(vulnerability_data["source"])
    sink = tuple(vulnerability_data["sink"])
    unsanitized_flows = vulnerability_data["unsanitized_flows"]
    sanitized_flows_data = vulnerability_data["sanitized_flows"]
    sanitized_flows = [parse_flow(flow_data) for flow_data in sanitized_flows_data]

    return Vulnerability(
        vulnerability, source, sink, unsanitized_flows, sanitized_flows
    )

def compare_json(output_f, target_f):
    # Load and validate JSON data from files
    with open(output_f, 'r') as f:
        json_data1 = json.load(f)

    with open(target_f, 'r') as f:
        json_data2 = json.load(f)

    if len(json_data1) != len(json_data2):
        return False

    if json_data1 == ["none"] and json_data2 == ["none"]:
        return True

    target = [parse_vulnerability(item) for item in json_data2]
    output = [parse_vulnerability(item) for item in json_data1]

    if len(target) != len(output):
        return False

    for output_idx in range(len(output)-1, -1, -1):
        for target_idx in range(len(target)-1, -1, -1):
            if output[output_idx] == target[target_idx]:
                target.pop(target_idx)
                output.pop(output_idx)
                break

    return not output and not target


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", '-o', help="Validate <output> file", default=False)
    parser.add_argument("--target", '-t', help="Check <output> vs <target_file>", default=False)

    args = parser.parse_args()

    if not (vars(args)['output'] and vars(args)['target']):
        print("Usage: python3 validate.py -o <output_file> -t <target_file>")
        exit(1)
    status = compare_json(vars(args)['output'], vars(args)['target'])
    if status:
        print(f"Output file is correct for {vars(args)['output']}")
        exit(0)
    print(f"Output file is incorrect for {vars(args)['output']}")
    exit(1)
