from lark import Lark, Transformer
from lark.exceptions import ParseError
from lark.lexer import Token
from lark.tree import Tree


class Task:
    def __init__(self, task_id, operator, operands):
        self.operator = operator
        self.operands = operands
        self.id = task_id


class String:
    def __init__(self, string_name, string_value, modifiers):
        self.str_name = string_name
        self.str_val = string_value
        self.modifiers = modifiers


class YaraTransformer(Transformer):
    def __init__(self):
        self.yara_rules = {}
        self.rule_strings = {}
        self.condition_queue = []
        self.string_queue = []
        self.imports = []
        self.includes = []
        self.tasks = {}
        self._task_id = 0

    def rules(self, args):
        p = 1

    def import_lib(self, args):
        self.imports.append(args[1].value)
        return args[1]

    def include_yara(self, args):
        self.includes.append(args[1].value)
        return args[1]

    def rule(self, args):
        rule_name = args[2].value
        if rule_name not in self.yara_rules:
            self.yara_rules[rule_name] = {}
            self.yara_rules[rule_name]['string'] = self.string_queue
            self.string_queue = []
            self.yara_rules[rule_name]['condition'] = self.condition_queue
            self.condition_queue = []
            # self.reset_task_id()
        else:
            raise Exception("Duplicate Rule {}".format(rule_name))
        return args

    def for_expression(self, args):
        return self.get_operand(args[0])

    def for_variables(self, args):
        tokens = []
        self.get_list_tokens(args, tokens)
        return tokens

    def strings(self, args):
        if len(args) > 0:
            return args[1]
        else:
            return args

    def text_string(self, args):
        args[0].type = "literal_string"
        return args[0]

    def regex_exp(self, args):
        args[0].type = "regex_expression"
        return args[0]

    def regexp_modifiers(self, args):
        return args

    def regexp_modifier(self, args):
        return args[0]

    def string_declarations(self, args):
        return args

    def string_declaration(self, args):
        s = String(args[0], args[1], args[2] )
        self.string_queue.append(s)
        return {'variable': args[0]}

    def string_identifier(self, args):
        return args[0].value

    def string_modifiers(self, args):
        return args

    def string_modifier(self, args):
        return args[0]

    def hex_string(self, args):
        return args[0]

    def hex_byte(self, args):
        args[0].type ='hex_byte'
        return args[0]





    def hex_modifiers(self, args):
        return args

    def hex_modifier(self, args):
        return args[0]

    def string_set(self, args):
        if len(args) == 1:
            if isinstance(args[0], list):
                return args[0]
            else:
                return self.get_operand(args[0])
        else:
            raise Exception("Not valid")

    def string_enumeration(self, args):
        tokens = []
        self.get_list_tokens(args, tokens)
        return tokens

    def string_enumeration_item(self, args):
        return self.get_operand(args[0])

    def condition(self, args):
        return args

    def expression(self, args):
        return self.add_new_task(args)

    def str_expression(self, args):
        return self.add_new_task(args)

    def other_expression(self, args):
        task = None
        if len(args) > 2 and isinstance(args[1], Token) and args[1].value == 'of':
            operands = [args[0]]
            self.extend_list(operands, args[2])
            task = Task(self.get_task_id(),
                        args[1],
                        operands)
        elif len(args) > 3 and isinstance(args[2], Token) and args[2].value == 'of':
            operands = args[0:2]
            self.extend_list(operands, args[3])
            task = Task(self.get_task_id(),
                        args[2],
                        operands)
        elif len(args) > 5 and isinstance(args[0], Token) and args[0].value == 'for':
            operands = []
            for i in range(1, len(args)):
                self.extend_list(operands, args[i])
            task = Task(self.get_task_id(),
                        args[0],
                        operands)
        else:
            task = self.add_new_task(args)

        if task:
            self.condition_queue.append(task)
        return task

    def other_primary_expression(self, args):
        task = None
        if len(args) == 2:
            task = Task(self.get_task_id(),
                        Token('index', 'index'),
                        args)
        elif len(args) == 3:
            raise NotImplementedError("other_primary_expression: STRING_COUNT IN range")
        else:
            task = args
        return task


    def identifier(self, args):
        task = None
        if len(args) == 1 and isinstance(args[0], Token):
            task = Task(self.get_task_id(),
                        "identifier",
                        args)
            self.condition_queue.append(task)
        elif len(args) == 2 and isinstance(args[0], Task):
            if isinstance(args[1], Token):
                args[0].operands.append(args[1])
            if isinstance(args[1], Tree):
                if args[1].data.value == 'index':
                    task = Task(self.get_task_id(),
                                "index",
                                [Token("Task", args[0].id), self.get_operand(args[1].children[0])])
                    self.condition_queue.append(task)
                elif args[1].data.value == 'arguments':
                    operands = [Token("Task", args[0].id)]
                    if args[1].children:
                        operands.extend([self.get_operand(x) for x in args[1].children[0]])
                    task = Task(self.get_task_id(),
                                "function",
                                operands)
                    self.condition_queue.append(task)
            task = args[0]

        return task

    def integer_function(self, args):
        return self.add_new_task(args)

    def integer_set(self, args):
        if len(args) == 1:
            if isinstance(args[0], list):
                return args[0]
            else:
                return self.get_operand(args[0])
        else:
            raise Exception("Not valid")

    def integer_enumeration(self, args):
        tokens = []
        self.get_list_tokens(args, tokens)
        return tokens

    def iterator(self, args):
        task = Task(self.get_task_id(),
                    Token("iterator", "iterator"),
                    self.get_operand(args[0]))
        return task

    def arguments_list(self, args):
        tokens = []
        self.get_list_tokens(args, tokens)
        return tokens

    def str_cmp_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def and_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def and_primary_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def not_expression(self, args):
        return self.add_new_unary_op_tasks(args)


    def add_primary_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def unary_primary_expression(self, args):
        return self.add_new_unary_op_tasks(args)

    def multiplication_primary_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def range(self, args):
        return self.add_new_task(args)

    ##################### internal functions ############################
    def add_new_binary_op_tasks(self, args):
        task = None
        if len(args) == 3:
            task = self.add_new_task(args)
        elif len(args) > 3:
            task = self.add_new_task(args[0:3])
            new_args = [task]
            self.extend_list(new_args, args[3:])
            task = self.add_new_binary_op_tasks(new_args)
        return task

    def add_new_unary_op_tasks(self, args):
        task = None
        if len(args) == 2:
            task = self.add_new_task(args)
        elif len(args) > 2:
            task = self.add_new_task(args[0:2])
            new_args = [task]
            self.extend_list(new_args, args[2:])
            task = self.add_new_binary_op_tasks(new_args)
        return task

    def add_new_task(self, args):
        res = None
        if len(args) == 2:
            res = self.create_unary_task(args)
        elif len(args) == 3:
            res = self.create_binary_task(args)
        else:
            p = 1

        if res:
            self.condition_queue.append(res)

        return res

    def create_unary_task(self, args):
        task = None
        if len(args) == 2:
            task = Task(self.get_task_id(), args[0], [self.get_operand(args[1])])
        return task

    def create_binary_task(self, args):
        task = None
        if len(args) == 3:
            task = Task(self.get_task_id(),
                        args[1],
                        [self.get_operand(args[0]), self.get_operand(args[2])])
        return task

    def get_list_tokens(self, args, tokens):
        task = None
        if len(args) == 1:
            if isinstance(args[0], list):
                for item in args[0]:
                    tokens.append(self.get_operand(item))
            else:
                tokens.append(self.get_operand(args[0]))

        elif len(args) > 1:
            if isinstance(args[0], list):
                for item in args[0]:
                    tokens.append(self.get_operand(item))
            else:
                tokens.append(self.get_operand(args[0]))

            del args[0]
            task = self.get_list_tokens(args, tokens)
        return task

    def get_operand(self, operand):
        res = operand
        if isinstance(operand, Task):
            res = Token("Task", operand.id)
        return res

    def get_task_id(self):
        res = self._task_id
        self._task_id += 1
        return res

    def reset_task_id(self):
        self._task_id = 0

    def extend_list(self, main_list, new_items):
        if isinstance(new_items, list):
            for item in new_items:
                main_list.append(self.get_operand(item))
        else:
            main_list.append(self.get_operand(new_items))
