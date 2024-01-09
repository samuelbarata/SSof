# Group 25

## Members

|                               Name                           | Student ID |
| ------------------------------------------------------------ | ---------- |
| [Pedro Tracana](mailto:pedro.tracana@tecnico.ulisboa.pt)     | ist193610  |
| [Samuel Barata](mailto:samuel.barata@tecnico.ulisboa.pt)     | ist194230  |
| [Sandra Castilho](mailto:sandra.castilho@tecnico.ulisboa.pt) | ist196765  |

## Tool

### Running the tool

To run the tool you should use the following command:
```sh
python3 py_analyser.py <slice.py> <pattern.json>
```

To run the tool in debug mode append the `--log-level DEBUG` flag:
```bash
python3 py_analyser.py <slice.py> <pattern.json> --log-level DEBUG
```

For more information about the tool run:
```bash
python3 py_analyser.py --help
```

## Testing Pipeline

There is a gitlab pipeline that tests the tool automatically. The pipeline can be found at [.gitlab-ci.yml](.gitlab-ci.yml).

### Stages
There are 2 stages in this pipeline:
- `Analyse`:
    - There is 1 job for each set of tests
    - Each job will run the tool for each test in the set. `Logs`, `Outputs` and `Expected Outputs` are saved in the artifacts
- `Test`:
    - There is 1 job for each set of tests
    - Each job will load the artifacts from the previous stage and compare the outputs with the expected outputs

<!--
## Development

Linting
```bash
autopep8 py_analyser.py --experimental --ignore E501 -i
```
-->

## Practical Test

A) The tool should not report uninitialized variables as sources

B) The pattern should have an extra field `interrupt` with values `"yes" | "no"` that indicates if the pattern should interrupt the analysis

- If a vulnerability is matched to this pattern, the analysis should stop and only this vulnerability should be reported
