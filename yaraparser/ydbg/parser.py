from email import message
import time
import json
import os
from .yara_transformer import *
from .yara_json_encoder import YaraEncoder


def parse(yara_rule_str):
    minified_json_str =''
    try:
        with open('yaraparser/ydbg/yara.grammar', 'r') as input_file:
            yara_grammar = ''.join(input_file.readlines())

        transformer = YaraTransformer()
        yara_parser = Lark(yara_grammar, parser='lalr', debug=True, transformer=transformer)
        yara_parsed_tree = yara_parser.parse(yara_rule_str)

        minified_json_str = json.dumps(transformer, cls=YaraEncoder, indent=None, separators=(',', ':'))
    except ParseError as exp:
        if len(exp.args)>0:
            minified_json_str = json.dumps({"error": exp.args[0] })
        else:
            minified_json_str = json.dumps({"error": f"[Grammar Error]\r\n[Location] Line: {exp.line}, Column:{exp.column}\r\n[Current token] type: {exp.token.type} value: {exp.token.value}\r\n[Expected token(s)] {', '.join(exp.expected)}",
                                            "error_obj": {
                                                "line": exp.line,
                                                "column": exp.column,
                                                "token_type": exp.token.type,
                                                "token_val": exp.token.value,
                                                "token_len": exp.token.end_pos - exp.token.start_pos + 1,
                                                "token_start_pos": exp.token.start_pos,
                                                "expected": ', '.join(exp.expected)
                                            }})
    except Exception as exp:
        minified_json_str = json.dumps({"error": exp.args[0] })

    return minified_json_str


def main():
    yara_grammar = ""
    with open('yara.grammar', 'r') as input_file:
        yara_grammar = ''.join(input_file.readlines())

    transformer = YaraTransformer()
    yara_parser = Lark(yara_grammar, parser='lalr', debug=True, transformer=transformer)

    yara_content = ""
    with open('..\\..\\internal\\test.yar', 'r', encoding="utf_8") as input_file:
        yara_content = ''.join(input_file.readlines())

    start = time.time()
    yara_parsed_tree = yara_parser.parse(yara_content)
    end = time.time()

    print((end - start))

    start = time.time()

    minified_json_str = json.dumps(transformer, cls=YaraEncoder, indent=None, separators=(',', ':'))
    open("..\\..\\internal\\test.json","w").write(minified_json_str)
    end = time.time()

    print((end - start))


if __name__ == "__main__":
    main()
