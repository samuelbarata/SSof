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
    """
    Defines a pattern that the tool can look for
    """

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
    """
    Defines a taint found by the tool
    """

    def __init__(self, source: str, source_line: int, pattern: str, implicit: bool = False):
        self.source = source
        self.source_line = source_line
        self.implicit = implicit
        self.pattern_name = pattern
        # WARNING: this list CANNOT be a default argument because default arguemnts are only created once and then copied [or referenced] to all instances of the class
        self.sanitizer = []

    def add_sanitizer(self, sanitizer: str, line: int):
        """
        Appends a sanitizer to the flow of the taint

        Parameters:
            - sanitizer (str): The name of the sanitizer function
            - line (int): The line where the sanitizer is called
        """
        self.sanitizer.append((sanitizer, line))

    def is_sanitized(self) -> bool:
        return len(self.sanitizer) > 0

    def __repr__(self) -> str:
        return f"Taint(Source: {self.source}, Source Line: {self.source_line}, Implicit: {self.implicit}, Sanitized: {self.is_sanitized()}, Pattern: {self.pattern_name})"


class VariableTaints:
    """
    Structure to save the taints of a variable and its attributes
    """

    def __init__(self):
        self.taints: list[Taint] = []
        self.initialized = False
        self.variables: dict[str, VariableTaints] = {}

    def assign_taints(self, taints):
        """
        Assigns the specified taints to the variable
        Marks the variable as initialized

        Parameters:
            - taints (list[Taint]): The taints to assign to the variable
        """
        self.taints = taints
        self.initialized = True

    def get_taints(self) -> list[Taint]:
        """
        Return the taints of the variable and all the taints of its attributes
        """
        ret = self.taints
        for var in self.variables:
            ret.extend(self.variables[var].get_taints())
        return ret


class Vulnerability:
    """
    Defines a vulnerability found by the tool
    """

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
        self.variables: dict[str, VariableTaints] = {}
        self.vulnerabilities: list[Vulnerability] = []
        logger.debug(f'Added patterns to Analyser:\n{self.patterns}')

    def export_results(self) -> str:
        """
        Exports the results of the analysis in the format specified by the project

        Returns:
            - str: The results of the analysis in JSON format
        """
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
        """
        Iterates an AST and analyses each statement
        """
        for statement in self.ast.body:
            self.analyse_statement(statement)

    def analyse_statement(self, statement) -> list[Taint]:
        """
        Matches a statement to the correct function to analyse it

        Parameters:
            - statement (ast.AST): The statement to analyse

        Returns:
            - list[Taint]: The taints found in the statement
        """
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
            case ast.Attribute():
                return self.attribute(statement)
            case ast.Compare():
                return self.compare(statement)
            case ast.If():
                return self.if_statement(statement)
            case ast.UnaryOp():
                return self.unary_op(statement)
            case _:
                logger.critical(f'Unknown statement type: {statement}')
                raise TypeError(f'Unknown statement type: {statement}')

    def unary_op(self, unary_op: ast.UnaryOp) -> list[Taint]:
        """
        Parameters:
            - unary_op (ast.UnaryOp): The unary operation to analyse

        Returns:
            - list[Taint]: The taints found in the unary operation
        """
        taints = self.analyse_statement(unary_op.operand)
        logger.debug(f'L{unary_op.lineno} {type(unary_op.op)}: {taints}')
        return taints

    def compare(self, compare: ast.Compare) -> list[Taint]:
        """
        Parameters:
            - compare (ast.Compare): The compare statement to analyse

        Returns:
            - list[Taint]: The taints found in the left and the right side of the compare statement
        """
        # Compare(left=Name(id='c', ctx=Load()), ops=[Lt()], comparators=[Constant(value=3)])
        taints = []
        taints.extend(self.analyse_statement(compare.left))
        for comparator in compare.comparators:
            taints.extend(self.analyse_statement(comparator))
        logger.debug(f'L{compare.lineno} {type(compare.ops[0])}: {taints}')
        return taints

    def if_statement(self, if_statement: ast.If) -> list[Taint]:

        taints = []
        statement_taints = self.analyse_statement(if_statement.test)
        # We can treat the if block and the else block as entire seperate ASTs.
        # We can create a new analyser instance for each blocks

        # TODO?: Maybe find a way to diferenciate logs originating from the main Analyser and the ones instanced here?

        analyser = [deepcopy(self)]
        if_taints = [analyser[0].analyse_statement(statement) for statement in if_statement.body]
        logger.debug(f'L{if_statement.lineno} IF: {if_taints}')

        if len(if_statement.orelse) > 0:
            analyser.append(deepcopy(self))
            else_taints = [analyser[1].analyse_statement(statement) for statement in if_statement.orelse]
            logger.debug(f'L{if_statement.lineno} ELSE: {else_taints}')

        # TODO: Merge if_taints and else_taints

        # taints = if_taints + else_taints
        logger.debug(f'L{if_statement.lineno}: {taints}')
        return taints

    def bin_op(self, bin_op: ast.BinOp) -> list[Taint]:
        """
        Parameters:
            - bin_op (ast.BinOp): The binary operation to analyse

        Returns:
            - list[Taint]: The taints found in the left and the right side of the binary operation
        """
        taints = self.analyse_statement(bin_op.left) + self.analyse_statement(bin_op.right)
        logger.debug(f'L{bin_op.lineno} {type(bin_op.op)}: {taints}')
        return taints

    def name(self, name: ast.Name) -> list[Taint]:
        """
        Returns the list of taints associated with a variable
        if the variable is uninitialized will return a taint for each pattern

        Parameters:
            - name (ast.Name): The name to analyse

        Returns:
            - list[Taint]: The taints found in the variable
        """
        # Name(id='a', ctx=Load())
        # Uninitialized variable
        if name.id not in self.variables:
            taints = [Taint(name.id, name.lineno, pattern.vulnerability) for pattern in self.patterns]
            logger.debug(f'L{name.lineno} Uninitialized variable {name.id}: {taints}')
            return taints

        taints = self.variables[name.id].get_taints()
        for pattern in self.patterns:
            # Variable is Source
            if name.id in pattern.sources:
                taints.append(Taint(name.id, name.lineno, pattern.vulnerability))
        logger.debug(f'L{name.lineno} {name.id}: {taints}')
        return taints

    def attribute(self, attribute, line=None) -> list[Taint]:
        """
        Parameters:
            - attribute (ast.Attribute): The attribute to analyse
            - attribute (list[str]): The list attributes already splited
            - line (int|None): The line where the attribute is present

        Returns:
            - list[Taint]: The taints found in the attribute
        """
        # Attribute(value=Name(id='c', ctx=Load()), attr='e', ctx=Store())
        taints = []
        # FIXME: I dont like this code AT ALL!!!
        # List of attributes already parsed
        if isinstance(attribute, list):
            attributes_list = attribute
            if len(attributes_list) == 0:
                return []
        # Attributes to parse
        else:
            attributes_list = self.get_name(attribute)
            line = attribute.lineno
        # END FIX-ME

        # Verificar a variavel
        if attributes_list[0] not in self.variables:
            # Criamos a variavel vazia
            variable_taint = VariableTaints()
            logger.debug(f'L{line} {attributes_list[0]}: didnt exist')
        else:
            # Guardamos a variavel para usar mais tarde
            # TODO?: tirar o deepcopy SE não escrevermos na variavel
            variable_taint = deepcopy(self.variables[attributes_list[0]])

        if not variable_taint.initialized:
            # Adicionamos taints de variavel nao inicializada
            taints.extend([Taint(attributes_list[0], line, pattern.vulnerability) for pattern in self.patterns])
            logger.debug(f'L{line} {attributes_list[0]}: was not initialized')
        else:
            taints.extend(variable_taint.get_taints())

        # Verificar os atributos da variavel
        for attribute_v in attributes_list[1:]:
            if attribute_v in variable_taint.variables:
                variable_taint = variable_taint.variables[attribute_v]
                # TODO?: might cause problems later
                if not variable_taint.initialized:
                    taints.extend([Taint(attribute_v, line, pattern.vulnerability) for pattern in self.patterns])
                # END TO-DO
                continue
            else:
                variable_taint = VariableTaints()
                taints.extend([Taint(attribute_v, line, pattern.vulnerability) for pattern in self.patterns])

        # taints = variable_taint.get_taints()
        logger.debug(f'L{line} {attributes_list}: {taints}')
        return taints

    def get_name(self, attribute) -> list[str]:
        """
        Parameters:
            - attribute (ast.Attribute): The attribute to analyse

        Returns:
            - list[str]: The list of attributes names

        Example:
            a.b.c -> ['a', 'b', 'c']
        """
        if isinstance(attribute, ast.Name):
            return [attribute.id]
        elif isinstance(attribute, ast.Attribute):
            return self.get_name(attribute.value) + [attribute.attr]
        else:
            logger.critical(f'Unknown attribute type: {attribute}')
            raise TypeError(f'Unknown attribute type: {attribute}')

    def assign(self, assignment: ast.Assign) -> list[Taint]:
        """
        Parameters:
            - assignment (ast.Assign): The assignment to analyse

        Returns:
            - list[Taint]: The taints transfered from the right side of the assignment to the left
        """
        # Assign(targets=[Name(id='a', ctx=Store())], value=Constant(value=''))
        # Assign(targets=[Attribute(value=Name(id='c', ctx=Load()), attr='e', ctx=Store())], value=Constant(value=0))
        # TODO?: Handle multiple targets
        assert len(assignment.targets) == 1, f'Assignments with multiple targets are not implemented'

        # Analyse the right side of the assignment
        taints = self.analyse_statement(assignment.value)
        attributes_list = self.get_name(assignment.targets[0])

        if attributes_list[0] not in self.variables:
            self.variables[attributes_list[0]] = VariableTaints()

        variable_taint = self.variables[attributes_list[0]]

        for attribute in attributes_list[1:]:
            if attribute not in variable_taint.variables:
                variable_taint.variables[attribute] = VariableTaints()

            variable_taint = variable_taint.variables[attribute]

        variable_taint.assign_taints(taints)
        logger.debug(f'L{assignment.lineno} {attributes_list}: {taints}')

        for pattern in self.patterns:
            for variable_name in attributes_list:
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
        """
        Parameters:
            - expression (ast.Expr): The expression to analyse

        Returns:
            - list[Taint]: The taints found in the expression
        """
        # Expr(value=Call(func=Name(id='e', ctx=Load()), args=[Name(id='b', ctx=Load())], keywords=[]))
        taints = self.analyse_statement(expression.value)
        logger.debug(f'L{expression.lineno}: {taints}')
        return taints

    def call(self, call: ast.Call) -> list[Taint]:
        """
        Parameters:
            - call (ast.Call): The call to analyse

        Returns:
            - list[Taint]: The taints retured by the call
        """
        # Call(func=Name(id='c', ctx=Load()), args=[], keywords=[])
        # Call(func=Attribute(value=Name(id='b', ctx=Load()), attr='m', ctx=Load()), args=[], keywords=[])

        # Taints from the arguments
        argument_taints = []
        # Taints matched by the pattern
        pattern_taints = []
        # Taints inherited from the class where the function is present
        attribute_taints = []
        func_attributes = self.get_name(call.func)
        logger.debug(f'L{call.lineno} {func_attributes}')

        for argument in call.args:
            argument_taints.extend(deepcopy(self.analyse_statement(argument)))

        # TODO: Verificar se fica assim ou se chamamos a função analyse_statement; desta forma tem a vantagem de que já corta a 'funcao em si'
        # FIXME: Este codigo ta actually feio do lado da função attribute... :(
        attribute_taints.extend(self.attribute(func_attributes[:-1], call.lineno))
        # END FIX-ME

        for pattern in self.patterns:
            for func_name in func_attributes:
                # Pattern Sources
                if func_name in pattern.sources:
                    pattern_taints.append(Taint(func_name, call.lineno, pattern.vulnerability))
                # Pattern Sinks
                if func_name in pattern.sinks:
                    # TODO: code duplicated in assign
                    for taint in argument_taints:
                        if taint.pattern_name == pattern.vulnerability:
                            # Deepcopy to prevent future sanitizers from affecting this taint
                            vuln = Vulnerability(pattern.vulnerability, deepcopy(taint), func_name, call.lineno)
                            self.vulnerabilities.append(vuln)
                            logger.info(f"Found vulnerability: {vuln.name}")
                            logger.debug(f"L{call.lineno} Vulnerability details: {vuln}")
                # Pattern Sanitizers
                if func_name in pattern.sanitizers:  # esta funcão sanitiza o pattern onde estou
                    for taint in argument_taints:  # em todos os taints que chegam aos argumentos desta função
                        if taint.pattern_name == pattern.vulnerability:  # se o taint se aplica ao pattern que estou a analisar
                            taint.add_sanitizer(func_name, call.lineno)  # adiciono o sanitizer ao taint
                            logger.info(f"L{call.lineno} Sanitized taint: {taint} for pattern: {pattern.vulnerability}")

        taints = pattern_taints + argument_taints + attribute_taints
        logger.debug(f'L{call.lineno} {func_name}: {taints}')
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

    logger.info(f'Starting {parser.prog}')
    logger.debug(f'Arguments passed to py_analyser: {args}')

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

    # Analyse slice
    analyser = Analyser(ast_py, patterns)
    analyser.analyse()

    # Export results
    output_file_name = f"{args.output_folder}/{extract_filename_without_extension(args.slice)}.output.json"
    make_folder_exist(args.output_folder)
    with open(output_file_name, 'w') as f:
        f.write(analyser.export_results())
