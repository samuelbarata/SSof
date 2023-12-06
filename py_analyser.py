import logging
import json
import argparse
import logging
import ast
import os

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

    # TODO: Implement analysis

    # TODO: Export results
    output_file_name = f"{args.output_folder}/{extract_filename_without_extension(args.slice)}.output.json"
    make_folder_exist(args.output_folder)
    with open(output_file_name, 'w') as f:
        f.write('[]')
