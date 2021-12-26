import json
from yara_transformer import *


class YaraEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Task):
            for i in obj.operands:
                p = 1
            operands = [{'name': x.type, 'val': x.value, 'line': x.line, 'col': x.column} for x in obj.operands]
            return {'id': obj.id, 'op': obj.operator, 'args': operands}
        elif isinstance(obj, YaraTransformer):
            return {'imports': obj.imports, 'includes': obj.includes, 'rules':obj.yara_rules}
        return json.JSONEncoder.default(self, obj)