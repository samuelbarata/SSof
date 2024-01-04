import logging
import json
import argparse
import logging
import ast
import os
from copy import deepcopy

# https://mattermost.rnl.tecnico.ulisboa.pt/ssof23/pl/jbfhkhw1g7b6tpsq94ua9tcthh
IMPLICITS_TO_EXPRESSIONS = True

# Safeguard to prevent infinite loops
MAX_CYCLE_ITERATIONS = 30

LOG_LEVELS = {
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL,
}

def hash_set(s):
    """
    Return a hash for a set of flows
    """
    h = 0
    for k in s:
        h += hash(k)
    return hash(h)

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
        self.sanitizer: set = set()

    def add_sanitizer(self, sanitizer: str, line: int):
        """
        Appends a sanitizer to the flow of the taint

        Parameters:
            - sanitizer (str): The name of the sanitizer function
            - line (int): The line where the sanitizer is called
        """
        sanitizer_tuple = (sanitizer, line)
        self.sanitizer.add(sanitizer_tuple)

    def is_sanitized(self) -> bool:
        return len(self.sanitizer) > 0

    def __eq__(self, other) -> bool:
        return isinstance(other, Taint) and \
            self.source == other.source and \
            self.source_line == other.source_line and \
            self.implicit == other.implicit and \
            self.pattern_name == other.pattern_name and \
            self.sanitizer == other.sanitizer

    def __hash__(self):
        return hash((self.source, self.source_line, self.implicit, self.pattern_name, hash_set(self.sanitizer)))

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

    def get_taints(self) -> list[Taint]:
        """
        Return the taints of the variable and all the taints of its attributes
        """
        ret = self.taints
        for var in self.variables:
            ret.extend(self.variables[var].get_taints())
        return ret

    def __eq__(self, other: object) -> bool:
        # We convert it to set to compare sice the order of the taints doesn't matter
        return isinstance(other, VariableTaints) and \
            set(self.taints) == set(other.taints) and \
            self.initialized == other.initialized and \
            self.variables == other.variables


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


class ImplicitStatement:
    """
    Structure to Store implicit taints for a single statement

    Parameters:
        - taints (list[Taint]): The taints found in the statement
        - statement (ast.AST): The statement
    """

    def __init__(self, taints: list[Taint], statement: ast.AST):
        self.taints = taints
        self.statement = statement
        self.lineno = statement.lineno

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ImplicitStatement) and \
            self.taints == other.taints and \
            self.statement == other.statement


class CycleStatus:
    """
    Structure to Store the while status

    Parameters:
        - iteration_count (int): How many times we "processed" this while cycle
        - variable_status (VariableTaints): The status of the previously executed while scycle, to match for changes
    """

    def __init__(self) -> None:
        self.iteration_count = 0
        self.variable_status = None

    def modifiy_variables(self, other: VariableTaints) -> bool:
        """
        Saves current variables state

        Parameters:
            - other (VariableTaints): The VariableTaints to assign to the WhileStatus

        Returns:
            - (bool) Whether the variables were modified or not
        """
        if self.variable_status != other:
            self.variable_status = deepcopy(other)
            return True
        return False

    def increment_iteration_count(self):
        self.iteration_count += 1
        if self.iteration_count >= MAX_CYCLE_ITERATIONS:
            logger.warning(f'Loop reached maximum iterations ({MAX_CYCLE_ITERATIONS})')
        return self.iteration_count

    def should_continue(self, variables: VariableTaints) -> bool:
        return (self.increment_iteration_count() < MAX_CYCLE_ITERATIONS and self.modifiy_variables(variables))


class Analyser:
    def __init__(self, ast, patterns):
        self.ast = ast
        self.patterns: list[Pattern] = patterns
        # Nota: não usamos dict[str, VariableTaints] porque facilita a recursividade
        self.variables: VariableTaints = VariableTaints()
        self.vulnerabilities: list[Vulnerability] = []
        logger.debug(f'Added patterns to Analyser:\n{self.patterns}')
        self.handler_reference: Analyser_Handler = None
        self.cycles_iterations: dict[int, CycleStatus] = {}
        self.debug_message = 'Analyser has not been run yet'

    def analyse(self, message=''):
        """
        Iterates an AST and analyses each statement

        Parameters:
            - message (str): This variable serves no purpose other than debugging
        """
        self.debug_message = message
        logger.info(f'Starting analysis of {self.ast}')
        logger.debug(f'Starting {message}')
        # Being a while allows us to modify the ast.body while iterating it
        while len(self.ast.body) > 0:
            stmt = self.ast.body.pop(0)
            self.handler_reference.log_stmt(self, stmt)
            self.analyse_statement(stmt, implicit=[])

    def analyse_statement(self, statement, implicit: list[Taint]) -> list[Taint]:
        """
        Matches a statement to the correct function to analyse it

        Parameters:
            - statement (ast.AST): The statement to analyse

        Returns:
            - list[Taint]: The taints found in the statement
        """
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
            case ast.BoolOp():
                return self.bool_op(statement, implicit)
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
            case ImplicitStatement():
                return self.implicit_statement(statement, implicit)
            case ast.While():
                return self.while_statement(statement, implicit)
            case ast.Tuple():
                return self.tuple_object(statement, implicit)
            case ast.Break():
                return self.break_statement(statement, implicit)
            case ast.Continue():
                return self.continue_statement(statement, implicit)
            case ast.For():
                return self.for_statement(statement, implicit)
            case ast.AugAssign():
                return self.aug_assign(statement, implicit)
            case _:
                logger.critical(f'Unknown statement type: {statement}')
                raise TypeError(f'Unknown statement type: {statement}')

    def aug_assign(self, aug_assign: ast.AugAssign, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - aug_assign (ast.AugAssign): The augmented assignment to analyse
            - implicit (list[Taint]): The implicit taints to pass to the augmented assignment

        Returns:
            - list[Taint]: The taints found in the augmented assignment
        """
        # AugAssign(target=Name(id='a', ctx=Store()), op=Add(), value=Constant(value=1))
        stmt = ast.Assign(targets=[aug_assign.target], value=ast.BinOp(left=aug_assign.target, op=aug_assign.op, right=aug_assign.value, lineno=aug_assign.lineno), lineno=aug_assign.lineno)
        stmt = ImplicitStatement(taints=implicit, statement=stmt)
        self.ast.body.insert(0, stmt)

    def break_statement(self, break_statement: ast.Break, implicit: list[Taint]) -> list[Taint]:
        """
        NOTE: Implicit taints created by break statements are not implemented

        Parameters:
            - break_statement (ast.Break): The break statement to analyse
            - implicit (list[Taint]): The implicit taints to pass to the break statement

        Returns:
            - list[Taint]: The taints found in the break statement
        """
        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []

        self.remove_until_cycle()
        # Removes the repetition of the cycle
        self.ast.body.pop(0)

        return taints

    def continue_statement(self, continue_statement: ast.Continue, implicit: list[Taint]) -> list[Taint]:
        """
        NOTE: Implicit taints created by continue statements are not implemented

        Parameters:
            - continue_statement (ast.Continue): The continue statement to analyse
            - implicit (list[Taint]): The implicit taints to pass to the continue statement

        Returns:
            - list[Taint]: The taints found in the continue statement
        """
        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []

        self.remove_until_cycle()

        return taints

    def bool_op(self, bool_op: ast.BoolOp, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - bool_op (ast.BoolOp): The boolean operation to analyse
            - implicit (list[Taint]): The implicit taints to pass to the boolean operation

        Returns:
            - list[Taint]: The taints found in the boolean operation
        """
        # BoolOp(op=And(), values=[Compare(...), Compare(...)])
        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []
        for value in bool_op.values:
            taints.extend(self.analyse_statement(value, implicit))
        logger.debug(f'L{bool_op.lineno} {type(bool_op.op)}: {taints}')
        return taints

    def tuple_object(self, tuple_object: ast.Tuple, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - tuple_object (ast.Tuple): The tuple to analyse
            - implicit (list[Taint]): The implicit taints to pass to the tuple elements

        Returns:
            - list[Taint]: The taints found in the tuple
        """
        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []

        for element in tuple_object.elts:
            taints.extend(self.analyse_statement(element, implicit))
        logger.debug(f'L{tuple_object.lineno} Tuple: {taints}')
        return taints

    def implicit_statement(self, implicit_statement: ImplicitStatement, implicit: list[Taint]) -> list[Taint]:
        """
        Handles the case of taints originated from implicit flows, differenciating the (implicit) taints of the
        if/else block from the rest of the analysis

        Parameters:
            - implicit_statement (ImplicitStatement): The implicit statement to analyse

        Returns:
            - list[Taint]: The taints found in the implicit statement
        """

        implicit_taints = implicit + implicit_statement.taints

        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []
        taints.extend(self.analyse_statement(implicit_statement.statement, implicit_taints))
        logger.debug(f'L{implicit_statement.statement.lineno} Implicit: {taints}')
        return taints

    def unary_op(self, unary_op: ast.UnaryOp, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - unary_op (ast.UnaryOp): The unary operation to analyse

        Returns:
            - list[Taint]: The taints found in the unary operation
        """
        taints = self.analyse_statement(unary_op.operand, implicit)
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
        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []
        taints.extend(self.analyse_statement(compare.left, implicit))
        for comparator in compare.comparators:
            taints.extend(self.analyse_statement(comparator, implicit))
        logger.debug(f'L{compare.lineno} {type(compare.ops[0])}: {taints}')
        return taints

    def if_statement(self, if_statement: ast.If, implicit: list[Taint]) -> list[Taint]:
        statement_taints = self.analyse_statement(if_statement.test, implicit)
        for taint in statement_taints:
            taint.implicit = True

        # We can treat the if block and the else block as entire seperate ASTs.
        # We can create a new analyser instance for each blocks

        if_flow = [ImplicitStatement(taints=statement_taints + implicit, statement=stmt) for stmt in if_statement.body]
        else_flow = [ImplicitStatement(taints=statement_taints + implicit, statement=stmt) for stmt in if_statement.orelse]

        # NOTE: else_analyser needs to be cloned before we modify the self.ast.body
        else_analyser = deepcopy(self)
        else_analyser.ast.body = else_flow + else_analyser.ast.body
        self.ast.body = if_flow + self.ast.body
        self.handler_reference.add_analyser(else_analyser, f'Entering Else block from line {if_statement.lineno}')

        # If stmt doesn't need to return a list of taints since it can never be used in an expression
        return []

    def for_statement(self, for_statement: ast.For, implicit: list[Taint]) -> list[Taint]:
        # For(target=Name(id='a', ctx=Store()), iter=Call(func=Name(id='range', ctx=Load()), args=[Call(func=Name(id='len', ctx=Load()), args=[Constant(value=7)], keywords=[])], keywords=[]), body=[Pass()], orelse=[])

        iter_taints = self.analyse_statement(for_statement.iter, implicit)
        for taint in iter_taints:
            taint.implicit = True

        # First time entering the for
        if for_statement.lineno not in self.cycles_iterations.keys():
            # Create Status object
            self.cycles_iterations[for_statement.lineno] = CycleStatus()

        for_status = self.cycles_iterations.get(for_statement.lineno)
        # Analyse not entering/exiting the while
        else_analyser = deepcopy(self)
        else_analyser.ast.body = [ImplicitStatement(taints=iter_taints + implicit, statement=stmt) for stmt in for_statement.orelse] + else_analyser.ast.body
        self.handler_reference.add_analyser(else_analyser, f'Exiting For block from line {for_statement.lineno} after {for_status.iteration_count} iterations')

        for_assign = ast.Assign(targets=[for_statement.target], value=for_statement.iter, lineno=for_statement.lineno)

        if for_status.should_continue(variables=self.variables):
            # Creates ImplicitStatements with the implicit taints from the while condition
            for_flow = [ImplicitStatement(taints=iter_taints + implicit, statement=stmt) for stmt in for_statement.body]
            # Resets AST to the state before the while was processed and prepends the statements inside the while
            flow = [for_assign] + for_flow + [for_statement]
            logger.debug(f'L{for_statement.lineno} While: preppending flow: {[stmt.lineno for stmt in flow]}')
            self.ast.body = flow + self.ast.body

        # For stmt doesn't need to return a list of taints since it can never be used in an expression
        return []

    def while_statement(self, while_statement: ast.While, implicit: list[Taint]) -> list[Taint]:
        # While(test=Compare(...), body=[...], type_ignores=[])

        # We can treat the while as an if block with an empty else
        statement_taints = self.analyse_statement(while_statement.test, implicit)
        for taint in statement_taints:
            taint.implicit = True

        # First time entering the while
        if while_statement.lineno not in self.cycles_iterations.keys():
            # Create Status object
            self.cycles_iterations[while_statement.lineno] = CycleStatus()

        while_status = self.cycles_iterations.get(while_statement.lineno)

        # Analyse not entering/exiting the while
        else_analyser = deepcopy(self)
        else_analyser.ast.body = [ImplicitStatement(taints=statement_taints + implicit, statement=stmt) for stmt in while_statement.orelse] + else_analyser.ast.body
        self.handler_reference.add_analyser(else_analyser, f'Exiting While block from line {while_statement.lineno} after {while_status.iteration_count} iterations')

        # if taints are still flowing through the while, analyse entering the while again (breanking condition)
        if while_status.should_continue(variables=self.variables):
            # Creates ImplicitStatements with the implicit taints from the while condition
            while_flow = [ImplicitStatement(taints=statement_taints + implicit, statement=stmt) for stmt in while_statement.body]
            # Resets AST to the state before the while was processed and prepends the statements inside the while
            flow = while_flow + [while_statement]
            logger.debug(f'L{while_statement.lineno} While: preppending flow: {[stmt.lineno for stmt in flow]}')
            self.ast.body = flow + self.ast.body

        # While stmt doesn't need to return a list of taints since it can never be used in an expression
        return []

    def bin_op(self, bin_op: ast.BinOp, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - bin_op (ast.BinOp): The binary operation to analyse

        Returns:
            - list[Taint]: The taints found in the left and the right side of the binary operation
        """
        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []
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
        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []

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
        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []

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
        # Assign(targets=[Tuple(elts=[Name(id='a', ctx=Store()), Name(id='b', ctx=Store())], ctx=Store())], value=Tuple(elts=[Constant(value=True), Call(func=Name(id='source', ctx=Load()), args=[], keywords=[])], ctx=Load()))

        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []

        # Analyse the right side of the assignment
        taints.extend(self.analyse_statement(assignment.value, implicit))

        target_list = []
        for target in assignment.targets:
            if isinstance(target, ast.Tuple):
                target_list.extend(target.elts)
            else:
                target_list.append(target)

        for target in target_list:
            attributes_list = self.get_name(target)

            variable_taint = self.variables
            for attribute in attributes_list:
                if attribute not in variable_taint.variables:  # undefined variable
                    variable_taint.variables[attribute] = VariableTaints()

                variable_taint = variable_taint.variables[attribute]

            # Filter out repeated taints
            taints_to_assign = list(set(taints + implicit))

            variable_taint.assign_taints(taints_to_assign)
            logger.debug(f'L{assignment.lineno} {attributes_list}: {taints}')

        for pattern in self.patterns:
            for variable_name in attributes_list:
                # Pattern Sinks
                self.match_sink(taints_to_assign, pattern, variable_name, assignment.lineno)

        return taints

    def expression(self, expression: ast.Expr, implicit: list[Taint]) -> list[Taint]:
        """
        Parameters:
            - expression (ast.Expr): The expression to analyse

        Returns:
            - list[Taint]: The taints found in the expression
        """
        # Expr(value=Call(func=Name(id='e', ctx=Load()), args=[Name(id='b', ctx=Load())], keywords=[]))
        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []

        taints.extend(self.analyse_statement(expression.value, implicit))
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
        if IMPLICITS_TO_EXPRESSIONS:
            taints = deepcopy(implicit)
        else:
            taints = []

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
                self.match_sink(argument_taints + implicit, pattern, func_name, call.lineno)
                # Pattern Sanitizers
                if func_name in pattern.sanitizers:  # esta funcão sanitiza o pattern onde estou
                    for taint in argument_taints:  # em todos os taints que chegam aos argumentos desta função
                        if taint.pattern_name == pattern.vulnerability:  # se o taint se aplica ao pattern que estou a analisar
                            taint.add_sanitizer(func_name, call.lineno)  # adiciono o sanitizer ao taint
                            logger.info(f"L{call.lineno} Sanitized taint: {taint} for pattern: {pattern.vulnerability}")

        taints.extend(pattern_taints + argument_taints + attribute_taints)
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

    def remove_until_cycle(self):
        """
        Removes all queued statements for analysis until the next while or for statement
        """
        while len(self.ast.body) > 0 and not isinstance(self.ast.body[0], (ast.While, ast.For)):
            self.ast.body.pop(0)


class Analyser_Handler():
    def __init__(self, slice):
        self.analysers: list[Analyser] = []
        self.slice = slice
        self.flows: dict[int, list] = {}

    def add_analyser(self, analyser: Analyser, message: str = ''):
        """
        Adds an analyser to the handler and runs the analyse function

        Parameters:
            - analyser (Analyser): The analyser to add to the handler
        """
        self.analysers.append(analyser)
        analyser.handler_reference = self
        self.flows[id(analyser)] = []
        logger.info(f'Added analyser to handler: {id(analyser)}')
        analyser.analyse(message)

    def log_stmt(self, analyser: Analyser, stmt):
        if logger.isEnabledFor(logging.DEBUG):
            self.flows[id(analyser)].append(stmt)

    def display_logs(self):
        if logger.isEnabledFor(logging.DEBUG):
            for analyser_id in self.flows.keys():
                lines = [stmt.lineno for stmt in self.flows[analyser_id]]
                flow = []
                for idx, line in enumerate(self.slice.splitlines()):
                    if idx + 1 in lines:
                        flow.append(f'{idx+1}: {line}')
                logger.debug(f'Flow {analyser_id}: {flow}')

    def export_results(self) -> str:
        """
        Exports the results of the analysis in the format specified by the project

        Returns:
            - str: The results of the analysis in JSON format
        """

        if logger.isEnabledFor(logging.DEBUG):
            self.display_logs()

        vulnerabilities: list[Vulnerability] = []
        for a in self.analysers:
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
            return json.dumps([])

        vulnerabilities = []
        for g in groups:
            vuln_out = {'vulnerability': g[0].name,
                        'source': [g[0].taint.source, g[0].taint.source_line],
                        'sink': [g[0].sink, g[0].sink_line],
                        'unsanitized_flows': 'no',
                        'sanitized_flows': []
                        }

            inserted_flows = set()
            sanitized_flows = []
            for vuln in g:
                if vuln.taint.is_sanitized():
                    h = hash_set(vuln.taint.sanitizer)
                    if h in inserted_flows:
                        pass
                    else:
                        inserted_flows.add(h)
                        sanitized_flows.append(tuple(vuln.taint.sanitizer))
                else:
                    vuln_out['unsanitized_flows'] = 'yes'
            vuln_out['sanitized_flows'] = sanitized_flows
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
        slices = f.read()
        ast_py = ast.parse(slices)
        logger.debug(ast.dump(ast_py))

    # Add main analyser to the handler
    handler = Analyser_Handler(slices)
    handler.add_analyser(Analyser(ast_py, patterns), 'Main Analyser')
    # the analyser will add more analysers as it runs

    # Export results
    output_file_name = f"{args.output_folder}/{extract_filename_without_extension(args.slice)}.output.json"
    make_folder_exist(args.output_folder)
    with open(output_file_name, 'w') as f:
        f.write(handler.export_results())
