import logging
import json
import argparse
import logging
import ast
import os
from copy import deepcopy

LOG_LEVELS = {
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL,
}


def make_folder_exist(folder):
    """
    Creates the specified folder if it doesn't exist
    """
    if not os.path.exists(folder):
        os.makedirs(folder)


def extract_filename_without_extension(file_path):
    """
    Returns the filename without the path and extension
    """
    filename_with_extension = os.path.basename(file_path)
    filename_without_extension, _ = os.path.splitext(filename_with_extension)
    return filename_without_extension


def visualizer(tree, name, folder):
    """
    Generate a png diagram of the AST

    The Diagram will be saved in the specified folder with the specified name

    Code adapted from: https://earthly.dev/blog/python-ast/
    """
    from graphviz import Digraph
    # Create a Graphviz Digraph object
    dot = Digraph(format='png', directory=folder)

    # Define a function to recursively add nodes to the Digraph
    def add_node(node, parent=None):
        node_name = str(node.__class__.__name__)
        dot.node(str(id(node)), node_name)
        if parent:
            dot.edge(str(id(parent)), str(id(node)))
        for child in ast.iter_child_nodes(node):
            add_node(child, node)
    # Add nodes to the Digraph
    add_node(tree)
    # Render the Digraph
    dot.render(name)


class Pattern:
    def __init__(self, object):
        self.vulnerability = object["vulnerability"]
        self.sources = object["sources"]
        self.sanitizers = object["sanitizers"]
        self.sinks = object["sinks"]
        self.implicit = False if object["implicit"] == 'no' else True
        logger.debug(f'Loaded pattern:\n{self}')

    def __str__(self):
        return f'Vulnerability: {self.vulnerability}\nSources: {self.sources}\nSanitizers: {self.sanitizers}\nSinks: {self.sinks}\nImplicit: {self.implicit}'

    def __repr__(self) -> str:
        return self.__str__()


class Taint:
    def __init__(self, source: str, source_line: int, implicit: bool = False, sanitized: bool = False):
        self.source = source
        self.source_line = source_line
        self.implicit = implicit
        self.sanitized = sanitized

    def __repr__(self) -> str:
        return f"Source: {self.source}, Source Line: {self.source_line}, Implicit: {self.implicit}, Sanitized: {self.sanitized}"


class Vulnerability:
    def __init__(self, name: str, taint: Taint, sink: str, sink_line: int):
        self.name = name
        self.taint = taint
        self.sink = sink
        self.sink_line = sink_line

    def to_dict(self) -> dict:
        return {'vulnerability': self.name, 'source': [self.taint.source, self.taint.source_line], 'sink': [self.sink, self.sink_line], 'unsanitized_flows': 'no' if self.taint.sanitized else 'yes', 'sanitized_flows': []}

    def __repr__(self) -> str:
        return f"Name: {self.name}, Sink: {self.sink}, Sink Line: {self.sink_line}, Taint: {self.taint}"


class Analyser:
    def __init__(self, ast, patterns):
        self.ast = ast
        self.patterns: list[Pattern] = patterns
        self.variables: dict[str, list[Taint]] = {}
        self.vulnerabilities: list[Vulnerability] = []
        logger.debug(f'Added patterns to Analyser:\n{self.patterns}')

    def export_results(self) -> str:
        if len(self.vulnerabilities) == 0:
            return json.dumps(['none'])
        return json.dumps([vuln.to_dict() for vuln in self.vulnerabilities], indent=4)

    def analyse(self):
        for statement in self.ast.body:
            self.analyse_statement(statement)

    def analyse_statement(self, statement) -> list[Taint]:
        match statement:
            case ast.Name():
                # 'Calling' a variable will allways return the taints associated with it
                return self.variables[statement.id]
            case ast.Assign():
                return self.assign(statement)
            case ast.Expr():
                return self.expression(statement)
            case ast.Call():
                return self.call(statement)
            case ast.Constant():
                return []  # A constant is never tainted

            case _:
                logger.critical(f'Unknown statement type: {statement}')
                raise TypeError(f'Unknown statement type: {statement}')

    def assign(self, assignment: ast.Assign) -> list[Taint]:
        # Assign(targets=[Name(id='a', ctx=Store())], value=Constant(value=''))
        # TODO?: Handle multiple targets
        # FIXME: REMOVE THIS LATER
        assert len(assignment.targets) == 1, f'Assignments with multiple targets are not implemented'
        # END FIX-ME
        variable_name = assignment.targets[0].id
        taint = self.analyse_statement(assignment.value)
        self.variables[variable_name] = taint
        logger.debug(f'Assigning {taint} to {variable_name}')

        return taint

    def expression(self, expression: ast.Expr) -> list[Taint]:
        # Expr(value=Call(func=Name(id='e', ctx=Load()), args=[Name(id='b', ctx=Load())], keywords=[]))
        return self.analyse_statement(expression.value)

    def call(self, call: ast.Call) -> list[Taint]:
        # Call(func=Name(id='c', ctx=Load()), args=[], keywords=[])
        argument_taints = []
        pattern_taints = []

        for argument in call.args:
            argument_taints.extend(self.analyse_statement(argument))

        for pattern in self.patterns:
            # Pattern Sources
            if call.func.id in pattern.sources:
                pattern_taints.append(Taint(call.func.id, call.lineno))
            # Pattern Sinks
            if call.func.id in pattern.sinks:
                for taint in argument_taints:
                    if taint.source in pattern.sources:
                        # Deepcopy to prevent future sanitizers from affecting this taint
                        vuln = Vulnerability(pattern.vulnerability, deepcopy(taint), call.func.id, call.lineno)
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found vulnerability: {vuln.name}")
                        logger.debug(f"Vulnerability details: {vuln}")
            # Pattern Sanitizers
            if call.func.id in pattern.sanitizers:
                # TODO: Implement me
                pass

        return pattern_taints + argument_taints


if __name__ == '__main__':
    project_root = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(description='Static analysis tool for identifying data and information flow violations')
    parser.add_argument('slice', help='python file to be spliced and analysed', type=str)
    parser.add_argument('patterns', help='patterns file to be checked', type=str)
    parser.add_argument('--log-level', default='INFO', help='log level', choices=['INFO', 'DEBUG', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('--log-file', default=f"{project_root}/analyser.log", help='log file location', type=str)
    parser.add_argument('--output-folder', default=f"{project_root}/output", help='output folder location', type=str)
    parser.add_argument('--visualize', help='Generate a png diagram of the AST', action='store_true')
    parser.add_argument('--visualize-folder', default=f"{project_root}/diagrams", help='AST diagrams folder location', type=str)
    args = parser.parse_args()

    # Setup logging
    logging_level = LOG_LEVELS.get(args.log_level, logging.INFO)
    logging.basicConfig(filename=args.log_file, level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger()

    logger.info(f'Starting py_analyser with arguments: {args}')

    # Load patterns file
    logger.info('Loading patterns file')
    logger.debug(f'Patterns file: {args.patterns}')
    with open(args.patterns, 'r') as f:
        patterns_dump = json.load(f)

    patterns = [Pattern(pattern) for pattern in patterns_dump]

    # Load slice file
    logger.info('Loading slice file')
    logger.debug(f'Slice file: {args.slice}')
    with open(args.slice, 'r') as f:
        ast_py = ast.parse(f.read())
        logger.debug(ast.dump(ast_py))
        if args.visualize:
            logger.debug('Generating AST Diagram')
            make_folder_exist(args.visualize_folder)
            visualizer(ast_py, name=extract_filename_without_extension(args.slice), folder=args.visualize_folder)

    analyser = Analyser(ast_py, patterns)
    analyser.analyse()

    output_file_name = f"{args.output_folder}/{extract_filename_without_extension(args.slice)}.output.json"
    make_folder_exist(args.output_folder)
    with open(output_file_name, 'w') as f:
        f.write(analyser.export_results())
