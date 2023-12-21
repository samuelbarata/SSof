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
        return f'\nVulnerability: {self.vulnerability}, Sources: {self.sources}, Sanitizers: {self.sanitizers}, Sinks: {self.sinks}, Implicit: {self.implicit}'

    def __repr__(self) -> str:
        return self.__str__()


class Taint:
    def __init__(self, source: str, source_line: int, pattern: str, sanitizer: list[tuple[str, int]] = list(), implicit: bool = False):
        self.source = source
        self.source_line = source_line
        self.implicit = implicit
        self.pattern_name = pattern
        self.sanitizer = sanitizer

    def add_sanitizer(self, sanitizer: str, line: int):
        # FIXME: This line doesn not work since it magically adds a new sanitizer to all taints instead of just this one
        # self.sanitizer.append((sanitizer, line))
        # END
        # The following line works, but its ugly
        self.sanitizer = self.sanitizer + [(sanitizer, line)]

    def is_sanitized(self) -> bool:
        return len(self.sanitizer) > 0

    def __repr__(self) -> str:
        return f"Taint(Source: {self.source}, Source Line: {self.source_line}, Implicit: {self.implicit}, Sanitized: {self.is_sanitized()}, Pattern: {self.pattern_name})"


class Vulnerability:
    def __init__(self, name: str, taint: Taint, sink: str, sink_line: int):
        self.name = name
        self.taint = taint
        self.sink = sink
        self.sink_line = sink_line

    def is_same_vulnerability(self, other) -> bool:
        return isinstance(other, Vulnerability) and \
            self.taint.pattern_name == other.taint.pattern_name and \
            self.taint.source == other.taint.source and \
            self.taint.source_line == other.taint.source_line and \
            self.sink == other.sink and \
            self.sink_line == other.sink_line

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

        groups: list[list[Vulnerability]] = []
        for vuln in self.vulnerabilities:
            matched = False
            for g in groups:
                if vuln.is_same_vulnerability(g[0]):
                    g.append(vuln)
                    matched = True
                    break
            if not matched:
                groups.append([vuln])

        vulnerabilities = []
        for g in groups:
            vuln_out = {'vulnerability': g[0].name,
                        'source': [g[0].taint.source, g[0].taint.source_line],
                        'sink': [g[0].sink, g[0].sink_line],
                        'unsanitized_flows': 'no',
                        'sanitized_flows': []
                        }
            for vuln in g:
                if vuln.taint.is_sanitized():
                    vuln_out['sanitized_flows'].append(list(vuln.taint.sanitizer))
                else:
                    vuln_out['unsanitized_flows'] = 'yes'
            vulnerabilities.append(vuln_out)

        # vulnerabilities = [vuln.to_dict() for vuln in self.vulnerabilities]
        vuln_names: dict[str, int] = {}  # name: [count, current]
        for vuln in vulnerabilities:
            value = vuln_names.get(vuln['vulnerability'], 0) + 1
            vuln_names[vuln['vulnerability']] = value

            vuln['vulnerability'] = f"{vuln['vulnerability']}_{value}"

        return json.dumps(vulnerabilities, indent=4)

    def analyse(self):
        for statement in self.ast.body:
            self.analyse_statement(statement)

    def analyse_statement(self, statement) -> list[Taint]:
        match statement:
            case ast.Name():
                return self.name(statement)
            case ast.Assign():
                return self.assign(statement)
            case ast.Expr():
                return self.expression(statement)
            case ast.Call():
                return self.call(statement)
            case ast.Constant():
                return []  # A constant is never tainted
            case ast.BinOp():
                return self.bin_op(statement)
            case _:
                logger.critical(f'Unknown statement type: {statement}')
                raise TypeError(f'Unknown statement type: {statement}')

    def bin_op(self, bin_op: ast.BinOp) -> list[Taint]:
        taints = self.analyse_statement(bin_op.left) + self.analyse_statement(bin_op.right)
        logger.debug(f'L{bin_op.lineno} {type(bin_op.op)}: {taints}')
        return taints

    def name(self, name: ast.Name) -> list[Taint]:
        # Name(id='a', ctx=Load())
        # Uninitialized variable
        if name.id not in self.variables:
            taints = [Taint(name.id, name.lineno, pattern.vulnerability) for pattern in self.patterns]
            logger.debug(f'L{name.lineno} Uninitialized variable {name.id}: {taints}')
            return taints

        taints = self.variables[name.id]
        for pattern in self.patterns:
            # Variable is Source
            if name.id in pattern.sources:
                taints.append(Taint(name.id, name.lineno, pattern.vulnerability))
        logger.debug(f'L{name.lineno} {name.id}: {taints}')
        return taints

    def assign(self, assignment: ast.Assign) -> list[Taint]:
        # Assign(targets=[Name(id='a', ctx=Store())], value=Constant(value=''))
        # TODO?: Handle multiple targets
        assert len(assignment.targets) == 1, f'Assignments with multiple targets are not implemented'

        variable_name = assignment.targets[0].id
        taints = self.analyse_statement(assignment.value)
        self.variables[variable_name] = taints
        logger.debug(f'L{assignment.lineno} {variable_name}: {taints}')

        for pattern in self.patterns:
            # Variable is Sink
            if variable_name in pattern.sinks:
                for taint in taints:
                    # TODO: code duplicated in call
                    if taint.pattern_name == pattern.vulnerability:
                        vuln = Vulnerability(pattern.vulnerability, deepcopy(taint), variable_name, assignment.lineno)
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found vulnerability: {vuln.name}")
                        logger.debug(f"Vulnerability details: {vuln}")

        return taints

    def expression(self, expression: ast.Expr) -> list[Taint]:
        # Expr(value=Call(func=Name(id='e', ctx=Load()), args=[Name(id='b', ctx=Load())], keywords=[]))
        taints = self.analyse_statement(expression.value)
        logger.debug(f'L{expression.lineno}: {taints}')
        return taints

    def call(self, call: ast.Call) -> list[Taint]:
        # Call(func=Name(id='c', ctx=Load()), args=[], keywords=[])
        argument_taints = []
        pattern_taints = []

        for argument in call.args:
            argument_taints.extend(deepcopy(self.analyse_statement(argument)))

        for pattern in self.patterns:
            # Pattern Sources
            if call.func.id in pattern.sources:
                pattern_taints.append(Taint(call.func.id, call.lineno, pattern.vulnerability))
            # Pattern Sinks
            if call.func.id in pattern.sinks:
                # TODO: code duplicated in assign
                for taint in argument_taints:
                    if taint.pattern_name == pattern.vulnerability:
                        # Deepcopy to prevent future sanitizers from affecting this taint
                        vuln = Vulnerability(pattern.vulnerability, deepcopy(taint), call.func.id, call.lineno)
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found vulnerability: {vuln.name}")
                        logger.debug(f"L{call.lineno} Vulnerability details: {vuln}")
            # Pattern Sanitizers
            if call.func.id in pattern.sanitizers:  # esta funcão sanitiza o pattern onde estou
                for taint in argument_taints:  # em todos os taints que chegam aos argumentos desta função
                    if taint.pattern_name == pattern.vulnerability:  # se o taint se aplica ao pattern que estou a analisar
                        taint.add_sanitizer(call.func.id, call.lineno)  # adiciono o sanitizer ao taint
                        logger.info(f"L{call.lineno} Sanitized taint: {taint} for pattern: {pattern.vulnerability}")

        taints = pattern_taints + argument_taints
        logger.debug(f'L{call.lineno} {call.func.id}: {taints}')
        return taints


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
    logging.basicConfig(filename=args.log_file, level=logging_level, format='%(asctime)s - %(levelname)s [%(funcName)s] %(message)s')
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
