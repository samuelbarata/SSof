#!/bin/bash

source ./test_env.sh
mkdir -p $LOGS_FOLDER
mkdir -p $OUTPUT_FOLDER
mkdir -p $EXPECTED_OUTPUT_FOLDER

# Analyse
for file in $SLICES_FOLDER/*.py; do
        slice_file=$(basename -- "$file")
        base_name_no_extension="${slice_file%.py}"
        patterns_file="${base_name_no_extension}.patterns.json"
        log_file="${base_name_no_extension}.log"
        expected_output_file="${base_name_no_extension}.output.json"
        #echo "Slices folder: $SLICES_FOLDER"
        #echo "Slice: $slice_file"
        #echo "Patterns: $patterns_file"
        #echo "Expected Output: $expected_output_file"
        cp $SLICES_FOLDER/${expected_output_file} $EXPECTED_OUTPUT_FOLDER/${expected_output_file}
        python3 $TOOL_NAME "$SLICES_FOLDER/${slice_file}" "$SLICES_FOLDER/${patterns_file}" --log-level $LOG_LEVEL --log-file $LOGS_FOLDER/$log_file --output-folder $OUTPUT_FOLDER 2> /dev/null || true
done

# Test
errors=0
for file in $EXPECTED_OUTPUT_FOLDER/*.output.json; do
	output_file=$(basename -- "$file")
	python3 validate.py --output $OUTPUT_FOLDER/${output_file} --target $EXPECTED_OUTPUT_FOLDER/${output_file} 2> /dev/null || let "errors += 1"
done
if [ $errors -gt 0 ]; then
	echo -e "There were $errors errors"
	exit 1
fi
