import time
import json
import os
from yara_transformer import *
from yara_json_encoder import YaraEncoder


def parse(yara_rule_str):
    with open('yaraparser\ydbg\yara.grammar', 'r') as input_file:
        yara_grammar = ''.join(input_file.readlines())

    transformer = YaraTransformer()
    yara_parser = Lark(yara_grammar, parser='lalr', debug=True, transformer=transformer)
    yara_parsed_tree = yara_parser.parse(yara_rule_str)

    minified_json_str = json.dumps(transformer, cls=YaraEncoder, indent=None, separators=(',', ':'))

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
