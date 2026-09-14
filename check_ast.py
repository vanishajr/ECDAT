import ast

with open('C:/Users/Shubh Mehta/Documents/Default Project/ecdat/benchmarks/evaluate_pass2.py', 'r') as f:
    content = f.read()

tree = ast.parse(content)
print('AST parsed successfully')

for node in ast.walk(tree):
    if isinstance(node, ast.ClassDef) and node.name == 'ComprehensiveEvaluator':
        print(f'Class: {node.name}')
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                print(f'  Method: {item.name}, lineno={item.lineno}, end_lineno={item.end_lineno}')
                for subnode in ast.walk(item):
                    if isinstance(subnode, ast.Return):
                        print(f'    Return at line {subnode.lineno}')