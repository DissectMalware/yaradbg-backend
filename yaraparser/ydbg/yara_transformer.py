from sys import setswitchinterval
from lark import Lark, Transformer
from lark.exceptions import ParseError
from lark.lexer import Token
from lark.tree import Tree


class Task:
    def __init__(self, task_id, operator, operands):
        self.operator = operator
        self.operands = operands
        self.id = task_id

    def start_pos(self):
        if isinstance(self.operator, Token):
            min_pos = self.operator.start_pos
            start_loc = 0
        else:
            min_pos = self.operands[0].start_pos
            start_loc = 1
        for i in range(start_loc, len(self.operands)):
            if isinstance(self.operands[i], Token) is False or isinstance(min_pos, int) is False:
                p  =1
            if self.operands[i].start_pos < min_pos:
                min_pos = self.operands[i].start_pos
        return min_pos

    def end_pos(self):
        if isinstance(self.operator, Token):
            max_pos = self.operator.end_pos
            start_loc = 0
        else:
            max_pos = self.operands[0].end_pos
            start_loc = 1
        for i in range(start_loc, len(self.operands)):
            if isinstance(self.operands[i], Token) is False or isinstance(max_pos, int) is False:
                p  =1

            if self.operands[i].end_pos > max_pos:
                max_pos = self.operands[i].end_pos
        return max_pos



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
        self.hex_virtual_instructions = []
        self.string_queue = []
        self.imports = []
        self.includes = []
        self.tasks = {}
        self._task_id = 0

        self._word_chars = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03,
            0xFE, 0xFF, 0xFF, 0x87, 0xFE, 0xFF, 0xFF, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]

        self._space_chars = [
            0x00, 0x3E, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]

        self._digit_chars = [ 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x03, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]


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
            self.yara_rules[rule_name]['start_line'] = args[2].line
            self.yara_rules[rule_name]['end_line'] = args[8].line
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

        args[1].type = "regex_expression_bytecode"
        args[1].value.append('match')
        args[1].start_pos = args[0].start_pos
        args[1].end_pos = args[2].end_pos
        
        return args[1]

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
        args[1].append('match')
        return Token('hex_exp_bytecode', args[1], start_pos=args[0].start_pos, end_pos=args[-1].end_pos)

    def hex_ignore_range(self, args):
        inst = []
        if len(args) == 1:
            args.append(Token('DASH', '-'))
            args.append(args[0])
        elif len(args) == 2:
            if args[0].value == "-":
                args.insert(0, Token('INTEGER', '0'))
            else:
                args.append(Token('INTEGER', '0') -1)

        inst.append(f'ignore {args[0].value},{args[2].value}')
        return inst

    def hex_expression(self, args):
        inst = []
        for arg in args:
            inst.extend(arg) if isinstance(arg, list) else inst.append(arg)
        return inst

    def hex_alt_bytes(self, args):
        if len(args) == 1:
            return args[0]
        else:
            inst = []
            inst.append(f"split [+1],[+{len(args[0])+1}]")
            inst.extend(args[0]) if isinstance(args[0], list) else inst.append(args[0])
            inst.append(f'jmp [+{len(args[1])+1}]')
            inst.extend(args[1]) if isinstance(args[1], list) else inst.append(args[1])
            return inst

    def hex_byte(self, args):
        args[0].type ='hex_byte'
        return f"chr {args[0].value}"

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
                                [Token("Task", args[0].id, 
                                    start_pos=args[0].start_pos(), 
                                    end_pos=args[0].end_pos()), 
                                self.get_operand(args[1].children[0])])
                    self.condition_queue.append(task)
                elif args[1].data.value == 'arguments':
                    operands = [Token("Task", args[0].id, 
                                    start_pos=args[0].start_pos(), 
                                    end_pos=args[0].end_pos())]
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
                    Token("iterator", "iterator", start_pos=self.get_operand(args[0]).start_pos, end_pos=self.get_operand(args[0]).end_pos),
                    [self.get_operand(args[0])])
        self.condition_queue.append(task)
        return task

    def arguments_list(self, args):
        tokens = []
        self.get_list_tokens(args, tokens)
        return tokens

    def str_cmp_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def and_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def not_expression(self, args):
        return self.add_new_unary_op_tasks(args)

    def primary_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def xor_primary_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def and_primary_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def shift_primary_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def add_primary_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def multiplication_primary_expression(self, args):
        return self.add_new_binary_op_tasks(args)

    def unary_primary_expression(self, args):
        return self.add_new_unary_op_tasks(args)

    def other_primary_expression(self, args):
        task = None
        if len(args) == 2:
            task = Task(self.get_task_id(),
                        Token('index', 'index', start_pos=self.get_operand(args[0]).start_pos, end_pos=self.get_operand(args[1]).end_pos),
                        [self.get_operand(args[0]), self.get_operand(args[1])])
            self.condition_queue.append(task)
        elif len(args) == 3:
            raise NotImplementedError("other_primary_expression: STRING_COUNT IN range")
        else:
            task = args
        return task

    def range(self, args):
        return self.add_new_task(args)


    ####################### Regex functions #############################
    def re_alternative(self, args):
        res = Token('re_alternative', [])

        if len(args) == 1:
            res.value = args[0].value
        else:
            res = Token('re_alternative', [])

            res.value.append(f'splitstay [+1],[+{len(args[0].value)+2}]')
            res.value.extend(args[0].value)
            res.value.append(f'jmp [+{len(args[1].value)+1}]')
            res.value.extend(args[1].value)

        return res

    def re_concatenation(self, args):
        val = []
        for i in args:
            val.extend(i.value)
        return Token('re_concatenation', val)

    def re_repeat(self, args):
        res = Token('repeat', [])
        if args[0].type == 're_single':
            if len(args)>1:
                range = False
                instructions = args[0].value
                is_greedy = len(args)==3
                if args[1].type == 're_range':
                    start, end = args[1].value
                    instructions = self.generate_range_program(instructions, start, end, is_greedy) 
                elif args[1].type == 'RE_PLUS':
                    instructions = self.generate_plus_program(instructions, is_greedy)
                elif args[1].type == 'RE_STAR':
                    instructions = self.generate_star_program(instructions, is_greedy)
                elif args[1].type == 'RE_QUESTION_MARK':
                    instructions = self.generate_question_mark_program(instructions, is_greedy)
                else:
                    raise Exception(f"[re_repeat] {args[1].type} is not implemented")
       
                res.value.extend(instructions)
            else:
                # repeat -> re_single
                
                return args[0]
        else:
            raise Exception(f'[re_repeat] {args[0].type} not implemented')
        return res

    def generate_question_mark_program(self, instructions, greedy):
        return self.generate_range_program(instructions, 0, 1, greedy)
    
    def generate_plus_program(self, instructions, greedy):
        # result = []
        # if not greedy:
        #     # none greedy
        #     result.extend(instructions)
        #     result.append(f'splitstay [+1],[-{len(instructions)}]')
        # else:
        #     # greedy
        #     result.extend(instructions)
        #     result.append(f'splitjmp [+1],[-{len(instructions)}]')
        return self.generate_range_program(instructions, 1, 'end', greedy)

    def generate_star_program(self, instructions, greedy):
        result = []
        if not greedy:
            # none greedy
            result.append(f'splitjmp [+1],[+{len(instructions)+2}]')
            result.extend(instructions)
            result.append(f'jmp [-{len(instructions)+1}]')
        else:
            # greedy
            result.append(f'splitstay [+1],[+{len(instructions)+2}]')
            result.extend(instructions)
            result.append(f'jmp [-{len(instructions)+1}]')
        return result

    def generate_range_program(self, instructions, start, end, greedy):

        result = []
        start = int(start) if isinstance(start, str) else start

        for i in range(start):
            result.extend(instructions)

        tmp = list()
        if(end != 'end'):
            end = int(end) if isinstance(end, str) else end
            for i in range(end - start, 0, -1):
                if not greedy:
                    # none greedy
                    tmp.append(f'splitjmp [+1],[+{(len(instructions)+1)*(i)}]')
                else:
                    # greedy
                    tmp.append( f'splitstay [+1],[+{(len(instructions)+1)*(i)}]')
            for i in range(end - start):
                tmp.extend(instructions)    

        else:
            tmp = self.generate_star_program(instructions, greedy)

        result.extend(tmp)
        return result

    def re_range(self, args):
        start = None
        end = None
        if len(args) == 1:
            if args[0].type == 'COMMA':
                start = 0
                end = 'end'
            else:
                start = args[0].value
                end = start
        elif len(args) == 2:
            if args[0].type == 'COMMA':
                start = 0
                end = args[1].value
            else:
                start = args[0].value
                end = 'end'
        else:
            start = args[0].value
            end = args[2].value

        return Token('re_range', [start, end] )
                

    def re_single(self, args):
        cmd = []
        if args[0].type == 'char_class' or \
            (args[0].type == 're_single_char' and isinstance(args[0].value, list)):
            cmd.append(f"chrc {','.join([hex(byte).replace('0x','') for byte in args[0].value])};")
        elif args[0].type == 're_single_char':
            cmd.append(f"chr {hex(args[0].value).replace('0x','')};")
        else:
            cmd = args[0].value
        
        return Token('re_single', cmd)

    def escaped_char(self, args):
        if len(args[1]) == 3 and args[1][0] == 'x':
            return int(args[1][1]+args[1][2], base=16)
        elif args[1] == 'a':
            return ord('\a')
        elif args[1] == 't':
            return ord('\t')
        elif args[1] == 'n':
            return ord('\n')
        elif args[1] == 'f':
            return ord('\f') 
        elif args[1] == 'r':
            return ord('\r')
        else:
            return ord(args[1].value)

    def re_single_char(self, args):
        val = None
        if isinstance(args[0], int):
            val = args[0]
        elif(args[0].value == '.'):
            val = [0xff] * 32
        elif(args[0].value == '\\w'):
            val = self._word_chars.copy()
        elif(args[0].value == '\\W'):
            val = self.not_bitmap(self._word_chars.copy())
        elif(args[0].value == '\\s'):
            val = self._space_chars.copy()
        elif(args[0].value == '\\S'):
            val = self.not_bitmap(self._space_chars.copy())
        elif(args[0].value == '\\d'):
            val = self._digit_chars.copy()
        elif(args[0].value == '\\D'):
            val = self.not_bitmap(self._digit_chars.copy())
        else:
            val = ord(args[0].value)
        return Token('re_single_char', val)

    def char_class(self, args):
        negation = False
        index = 0
        if args[0] == '^':
            negation = False
            index = 1

        state = 0
        bitmap = [0] * 32
        while index < len(args):
            current_char = args[index].value
            if isinstance(current_char, int):
                    self.add_to_bitmap(bitmap, current_char)
                    index += 1
            elif isinstance(current_char, list) and len(current_char) == 32:
                self.or_bitmaps(bitmap, current_char)
                index += 1
            elif( isinstance(current_char, str) and index+1 < len(args) -1 and args[index+1] == '-'):
                    start = ord(current_char)
                    end = ord(args[index+2].value)
                    range_bitmap = self.get_bitmap(start, end)
                    self.or_bitmaps(bitmap, range_bitmap)
                    index += 3
            else:
                raise Exception('char_class: Unknown token')

        return Token('char_class', bitmap)

                
    ##################### internal functions ############################
    def get_bitmap(self, range_start, range_end):
        bitmap = [0]* 32
        for i in range(range_start, range_end +1):
            self.add_to_bitmap(bitmap, i)
        return bitmap

    def or_bitmaps(self, base, new_bitmap):
        if(len(base) != 32 or len(new_bitmap)!= 32):
            raise Exception('[or_bitmaps] arguments must be bitmap arrays (len(array)==32)')

        for i in range(0, 32):
            base[i] |= new_bitmap[i]

    def not_bitmap(self, bitmap):
        if(len(bitmap) != 32 ):
            raise Exception('[not_bitmaps] argument must be a bitmap array (len(array)==32)')

        for i in range(0, 32):
            bitmap[i] ^= 0xFF

    def add_to_bitmap(self, bitmap, number):
        bitmap[number>>3] |= 1<<(number&7)


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
            res = Token("Task", operand.id, start_pos=operand.start_pos(), end_pos=operand.end_pos())
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
