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
    os.makedirs(folder, exist_ok=True)


def extract_filename_without_extension(file_path):
    """
    Returns the filename without the path and extension
    """
    return os.path.splitext(os.path.basename(file_path))[0]


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
        self.sanitizer = []

    def add_sanitizer(self, sanitizer: str, line: int):
        """
        Appends a sanitizer to the flow of the taint

        Parameters:
            - sanitizer (str): The name of the sanitizer function
            - line (int): The line where the sanitizer is called
        """
        self.sanitizer.append((sanitizer, line))

    def merge_sanitizers(self, other):
        """
        Merges the sanitizers of two taints
        """
        if self != other:
            logger.critical(f'Cannot merge different taints')
            raise ValueError(f'Cannot merge different taints')
        for sanitizer in other.sanitizer:
            if sanitizer not in self.sanitizer:
                # TODO: this might cause problems later because the sanitizer can be a list
                self.sanitizer.append(deepcopy(sanitizer))

    def is_sanitized(self) -> bool:
        return len(self.sanitizer) > 0

    def __eq__(self, other) -> bool:
        return isinstance(other, Taint) and \
            self.source == other.source and \
            self.source_line == other.source_line and \
            self.implicit == other.implicit and \
            self.pattern_name == other.pattern_name

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

    def get_variables(self) -> list[str]:
        """
        Returns the list of variables that are attributes of this variable
        """
        return list(self.variables.keys())

    def assign_taints(self, taints):
        """
        Assigns the specified taints to the variable
        Marks the variable as initialized

        Parameters:
            - taints (list[Taint]): The taints to assign to the variable
        """
        self.taints = taints
        self.initialized = True

    def merge_taints(self, taints: list[Taint]):
        for new_taint in taints:
            if new_taint in self.taints:
                for taint in self.taints:
                    if taint == new_taint:
                        taint.merge_sanitizers(new_taint)
                        break
            else:
                self.taints.append(deepcopy(new_taint))

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


class ImplicitBlock:
    """
    Structure to Store implicit taints for a block of statements

    Parameters:
        - taints (list[Taint]): The taints found in the block
        - statements (list[ast.AST]): The statements that are part of the block
    """

    def __init__(self, taints: list[Taint], statements: list[ast.AST]):
        self.taints = taints
        self.body = statements


class Analyser:
    def __init__(self, ast, patterns):
        self.ast = ast
        self.patterns: list[Pattern] = patterns
        # Nota: não usamos dict[str, VariableTaints] porque facilita a recursividade
        self.variables: VariableTaints = VariableTaints()
        self.vulnerabilities: list[Vulnerability] = []
        logger.debug(f'Added patterns to Analyser:\n{self.patterns}')
        self.handler_reference: Analyser_Handler = None
        self.candeeiros = True  # Whether the analyser is alive or not

    def abort(self):
        """
        Aborts the analysis
        """
        self.candeeiros = False
        logger.info(f'Aborting analysis of {self.ast}')

    def analyse(self):
        """
        Iterates an AST and analyses each statement
        """
        logger.info(f'Starting analysis of {self.ast}')
        for statement in self.ast.body:
            if not self.candeeiros:  # Analysis was aborted
                break
            self.analyse_statement(statement, [])

    def analyse_statement(self, statement, implicit: list[Taint]) -> list[Taint]:
        """
        Matches a statement to the correct function to analyse it

        Parameters:
            - statement (ast.AST): The statement to analyse

        Returns:
            - list[Taint]: The taints found in the statement
        """
        if not self.candeeiros:  # ignore the vulnerabilities after aborting the analysis
            return []

        match statement:
            case ast.Name():
                return self.name(statement, implicit)
            case ast.Assign():
                return self.assign(statement, implicit)
            case ast.Expr():
                return self.expression(statement, implicit)
            case ast.Call():
                return self.call(statement, implicit)
            case ast.Constant():
                return []  # A constant is never tainted
            case ast.BinOp():
                return self.bin_op(statement, implicit)
            case ast.Attribute():
                return self.attribute(statement, implicit)
            case ast.Compare():
                return self.compare(statement, implicit)
            case ast.If():
                return self.if_statement(statement, implicit)
            case ast.UnaryOp():
                return self.unary_op(statement, implicit)
            case ast.Pass():
                return []
            case ImplicitBlock():
                return self.implicit_block(statement, implicit)
            case _:
                logger.critical(f'Unknown statement type: {statement}')
                raise TypeError(f'Unknown statement type: {statement}')

    def implicit_block(self, implicit_block: ImplicitBlock, implicit: list[Taint]) -> list[Taint]:
        """
        Handles the case of taints originated from implicit flows, differenciating the (implicit) taints of the if/else block from the rest of the analysis

        Parameters:
            - implicit_block (ImplicitBlock): The implicit block to analyse

        Returns:
            - list[Taint]: The taints found in the implicit block
        """

        taints = deepcopy(implicit)
        taints.extend(implicit_block.taints)

        implicit = deepcopy(implicit)
        implicit.extend(implicit_block.taints)  # used on nested ifs

        taints.extend([self.analyse_statement(statement, implicit) for statement in implicit_block.body])
        return taints

    def unary_op(self, unary_op: ast.UnaryOp, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - unary_op (ast.UnaryOp): The unary operation to analyse

        Returns:
            - list[Taint]: The taints found in the unary operation
        """
        taints = self.analyse_statement(unary_op.operand, implicit) + deepcopy(implicit)
        logger.debug(f'L{unary_op.lineno} {type(unary_op.op)}: {taints}')
        return taints

    def compare(self, compare: ast.Compare, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - compare (ast.Compare): The compare statement to analyse

        Returns:
            - list[Taint]: The taints found in the left and the right side of the compare statement
        """
        # Compare(left=Name(id='c', ctx=Load()), ops=[Lt()], comparators=[Constant(value=3)])
        taints = deepcopy(implicit)
        taints.extend(self.analyse_statement(compare.left, implicit))
        for comparator in compare.comparators:
            taints.extend(self.analyse_statement(comparator, implicit))
        logger.debug(f'L{compare.lineno} {type(compare.ops[0])}: {taints}')
        return taints

    def if_statement(self, if_statement: ast.If, implicit: list[Taint]) -> list[Taint]:

        taints = deepcopy(implicit)
        statement_taints = self.analyse_statement(if_statement.test, implicit)
        for taint in statement_taints:
            taint.implicit = True

        taints.extend(statement_taints)
        # We can treat the if block and the else block as entire seperate ASTs.
        # We can create a new analyser instance for each blocks

        # WARNING: From this point forward the self.ast.body will be rendered unusable
        #          new analyser instances will be created the modified ast.body

        if_implicit_block = ImplicitBlock(statements=if_statement.body, taints=statement_taints)
        else_implicit_block = ImplicitBlock(statements=if_statement.orelse, taints=statement_taints)

        def get_path_to_statement(statement, path, current=self.ast.body) -> list[ast.AST]:
            if isinstance(current[0], ImplicitBlock):
                path.append(current[0])
                return get_path_to_statement(statement, path, current[0].body)
            return path

        # Iterates the AST until it finds the ImplicitBlock we're in or the ast.body if we're in the main block
        # Removes all statements before the ImplicitBlock
        tmp = self.ast.body
        for _ in range(len(get_path_to_statement(if_statement, path=[]))):
            while not (isinstance(tmp[0], ImplicitBlock) or isinstance(tmp[0], ast.If)):
                tmp.pop(0)
            if isinstance(tmp[0], ImplicitBlock):
                tmp = tmp[0].body

        # tmp points to the ImplicitBlock we're in or to the ast.body if we're in the main block
        # Removes all statements before the if block
        while tmp[0] != if_statement:
            tmp.pop(0)
        tmp.pop(0)

        new_if_ast_body = [if_implicit_block] + self.ast.body
        new_else_ast_body = [else_implicit_block] + self.ast.body

        analyser_if = deepcopy(self)
        analyser_if.ast.body = new_if_ast_body
        analyser_else = deepcopy(self)
        analyser_else.ast.body = new_else_ast_body

        self.handler_reference.add_analyser(analyser_if)
        self.handler_reference.add_analyser(analyser_else)
        self.abort()

        return []

    def bin_op(self, bin_op: ast.BinOp, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - bin_op (ast.BinOp): The binary operation to analyse

        Returns:
            - list[Taint]: The taints found in the left and the right side of the binary operation
        """
        taints = deepcopy(implicit)
        taints.extend(self.analyse_statement(bin_op.left, implicit) + self.analyse_statement(bin_op.right, implicit))
        logger.debug(f'L{bin_op.lineno} {type(bin_op.op)}: {taints}')
        return taints

    def name(self, name: ast.Name, implicit: list[Taint]) -> list[Taint]:
        """
        Returns the list of taints associated with a variable
        if the variable is uninitialized will return a taint for each pattern

        Parameters:
            - name (ast.Name): The name to analyse

        Returns:
            - list[Taint]: The taints found in the variable
        """
        taints = deepcopy(implicit)
        # Name(id='a', ctx=Load())
        # Variable was never assigned a value [Uninitialized]
        if name.id not in self.variables.get_variables():
            taints.extend([Taint(name.id, name.lineno, pattern.vulnerability) for pattern in self.patterns])
            logger.debug(f'L{name.lineno} Uninitialized variable {name.id}: {taints}')
            return taints

        # Get taints from initialized variable
        taints.extend(deepcopy(self.variables.variables[name.id].get_taints()))
        # Check if variable was not initialized in at least one flow
        if not self.variables.variables[name.id].initialized:
            taints.extend([Taint(name.id, name.lineno, pattern.vulnerability) for pattern in self.patterns])
        # Check if variable is source
        for pattern in self.patterns:
            if name.id in pattern.sources:
                taints.append(Taint(name.id, name.lineno, pattern.vulnerability))

        logger.debug(f'L{name.lineno} {name.id}: {taints}')
        return taints

    def attribute(self, attribute: ast.Attribute, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - attribute (ast.Attribute): The attribute to analyse

        Returns:
            - list[Taint]: The taints found in the attribute
        """
        # Attribute(value=Name(id='c', ctx=Load()), attr='e', ctx=Store())
        taints = deepcopy(implicit)

        # analyse the other attributes [c]
        for taint in self.analyse_statement(attribute.value, implicit):
            # Will not add repeated taints;
            # taints from a.b.c will also be discovered on a.b and a
            if taint not in taints:
                taints.append(taint)

        # check if attribute is source [e]
        for pattern in self.patterns:
            # check if attribute is source
            if attribute.attr in pattern.sources:
                taints.append(Taint(attribute.attr, attribute.lineno, pattern.vulnerability))

        # get attribute from analyser variables
        attributes_list = self.get_name(attribute)
        variable_taint = self.variables
        for attribute_v in attributes_list:
            if attribute_v in variable_taint.variables:
                variable_taint = variable_taint.variables[attribute_v]
            else:
                variable_taint = VariableTaints()

        # get taints from variable
        taints.extend(deepcopy(variable_taint.taints))

        # taints from uninitialized variable
        if not variable_taint.initialized:
            taints.extend([Taint(attribute.attr, attribute.lineno, pattern.vulnerability) for pattern in self.patterns])

        logger.debug(f'L{attribute.lineno} {attributes_list}: {taints}')
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

    def assign(self, assignment: ast.Assign, implicit: list[Taint]) -> list[Taint]:
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

        taints = deepcopy(implicit)
        # Analyse the right side of the assignment
        taints.extend(self.analyse_statement(assignment.value, implicit))
        attributes_list = self.get_name(assignment.targets[0])

        variable_taint = self.variables

        for attribute in attributes_list:
            if attribute not in variable_taint.variables:  # undefined variable
                variable_taint.variables[attribute] = VariableTaints()

            variable_taint = variable_taint.variables[attribute]

        variable_taint.assign_taints(taints)
        logger.debug(f'L{assignment.lineno} {attributes_list}: {taints}')

        for pattern in self.patterns:
            for variable_name in attributes_list:
                # Pattern Sinks
                self.match_sink(taints, pattern, variable_name, assignment.lineno)

        return taints

    def expression(self, expression: ast.Expr, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - expression (ast.Expr): The expression to analyse

        Returns:
            - list[Taint]: The taints found in the expression
        """
        # Expr(value=Call(func=Name(id='e', ctx=Load()), args=[Name(id='b', ctx=Load())], keywords=[]))
        taints = self.analyse_statement(expression.value, implicit)
        logger.debug(f'L{expression.lineno}: {taints}')
        return taints

    def call(self, call: ast.Call, implicit: list[Taint]) -> list[Taint]:
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
            argument_taints.extend(deepcopy(self.analyse_statement(argument, implicit)))

        if isinstance(call.func, ast.Attribute):
            attribute_taints.extend(self.analyse_statement(call.func.value, implicit))

        for pattern in self.patterns:
            for func_name in func_attributes:
                # Pattern Sources
                if func_name in pattern.sources:
                    pattern_taints.append(Taint(func_name, call.lineno, pattern.vulnerability))
                # Pattern Sinks
                self.match_sink(argument_taints, pattern, func_name, call.lineno)
                # Pattern Sanitizers
                if func_name in pattern.sanitizers:  # esta funcão sanitiza o pattern onde estou
                    for taint in argument_taints:  # em todos os taints que chegam aos argumentos desta função
                        # Implicit taints are not sanitizable
                        if taint.implicit:
                            continue
                        if taint.pattern_name == pattern.vulnerability:  # se o taint se aplica ao pattern que estou a analisar
                            taint.add_sanitizer(func_name, call.lineno)  # adiciono o sanitizer ao taint
                            logger.info(f"L{call.lineno} Sanitized taint: {taint} for pattern: {pattern.vulnerability}")

        taints = pattern_taints + argument_taints + attribute_taints
        logger.debug(f'L{call.lineno} {func_name}: {taints}')
        return taints

    def match_sink(self, taints: list[Taint], pattern, name, lineno):
        if name in pattern.sinks:
            for taint in taints:
                if taint.pattern_name == pattern.vulnerability:
                    # Deepcopy to prevent future sanitizers from affecting this taint
                    vuln = Vulnerability(pattern.vulnerability, deepcopy(taint), name, lineno)
                    self.vulnerabilities.append(vuln)
                    logger.info(f"Found vulnerability: {vuln.name}")
                    logger.debug(f"L{lineno} Vulnerability details: {vuln}")


class Analyser_Handler():
    def __init__(self):
        self.analysers: list[Analyser] = []

    def add_analyser(self, analyser: Analyser):
        """
        Adds an analyser to the handler and runs the analyse function

        Parameters:
            - analyser (Analyser): The analyser to add to the handler
        """
        self.analysers.append(analyser)
        analyser.handler_reference = self
        analyser.analyse()

    def export_results(self) -> str:
        """
        Exports the results of the analysis in the format specified by the project

        Returns:
            - str: The results of the analysis in JSON format
        """

        vulnerabilities: list[Vulnerability] = []
        for a in self.analysers:
            if a.candeeiros:  # Analyser was not aborted
                vulnerabilities.extend(a.vulnerabilities)
        groups: list[list[Vulnerability]] = []
        for vuln in vulnerabilities:
            # Ignore implicit vulnerabilities for patterns that don't require it
            skip_implicit = False
            for pattern in patterns:
                if vuln.taint.pattern_name == pattern.vulnerability:
                    if not pattern.implicit and vuln.taint.implicit:
                        skip_implicit = True
                        break
            if skip_implicit:
                continue

            matched = False
            for g in groups:
                if vuln.is_same_vulnerability(g[0]):
                    g.append(vuln)
                    matched = True
                    break
            if not matched:
                groups.append([vuln])

        if len(groups) == 0:
            return json.dumps(['none'])

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
                    if vuln.taint.sanitizer not in vuln_out['sanitized_flows']:
                        vuln_out['sanitized_flows'].append(list(vuln.taint.sanitizer))
                    else:
                        logger.warning(f'Vulnerability {vuln.name} has repeated sanitizers; there might be a bug')
                else:
                    vuln_out['unsanitized_flows'] = 'yes'
            vulnerabilities.append(vuln_out)

        return json.dumps(vulnerabilities, indent=4)


if __name__ == '__main__':
    project_root = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(description='Static analysis tool for identifying data and information flow violations')
    parser.add_argument('slice', help='python file to be spliced and analysed', type=str)
    parser.add_argument('patterns', help='patterns file to be checked', type=str)
    parser.add_argument('--log-level', default='INFO', help='log level', choices=['INFO', 'DEBUG', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('--log-file', default=f"{project_root}/analyser.log", help='log file location', type=str)
    parser.add_argument('--output-folder', default=f"{project_root}/output", help='output folder location', type=str)
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

    # Add main analyser to the handler
    handler = Analyser_Handler()
    handler.add_analyser(Analyser(ast_py, patterns))
    # the analyser will add more analysers as it runs

    # Export results
    output_file_name = f"{args.output_folder}/{extract_filename_without_extension(args.slice)}.output.json"
    make_folder_exist(args.output_folder)
    with open(output_file_name, 'w') as f:
        f.write(handler.export_results())
