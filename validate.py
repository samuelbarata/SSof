#!/bin/python3

import json
import argparse


def compare_json(output, target):
    # Load and validate JSON data from files
    with open(output, 'r') as f:
        json_data1 = json.load(f)

    with open(target, 'r') as f:
        json_data2 = json.load(f)

    if len(json_data1) != len(json_data2):
        return False

    if json_data1 == ["none"] and json_data2 == ["none"]:
        return True

    try:
        # Convert JSON data to string and compare
        json_data1_sorted = sorted(json_data1, key=lambda x: x['vulnerability'])
        json_data2_sorted = sorted(json_data2, key=lambda x: x['vulnerability'])
    except:
        return False

    return json_data1_sorted == json_data2_sorted


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
