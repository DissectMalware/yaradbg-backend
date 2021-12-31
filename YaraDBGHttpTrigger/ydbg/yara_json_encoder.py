import json
from .yara_transformer import *


class YaraEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Task):
            for i in obj.operands:
                p = 1
            operands = [{'name': x.type, 'val': x.value, 'line': x.line, 'col': x.column} for x in obj.operands]
            return {'id': obj.id, 'op': obj.operator, 'args': operands}
        elif isinstance(obj, String):
            modifiers = [{'modifier': x.value} for x in obj.modifiers]
            if isinstance(obj.str_val, Tree):
                return {'str_name': obj.str_name, 'val': self.tree_to_dict(obj.str_val), 'type': obj.str_val.data.value,
                        'modifiers': modifiers}
            else:
                return {'str_name': obj.str_name, 'val': obj.str_val.value, 'type': obj.str_val.type, 'modifiers': modifiers}
        elif isinstance(obj, YaraTransformer):
            return {'imports': obj.imports, 'includes': obj.includes, 'rules':obj.yara_rules}
        return json.JSONEncoder.default(self, obj)

    def tree_to_dict(self, tree):
        root = tree.__dict__.copy()
        root['children'] = []
        root['rule'] = root['data'].value
        del root['data']
        del root['_meta']
        for child in tree.children:
            if isinstance(child, Tree):
                root['children'].append(self.tree_to_dict( child))
            else:
                root['children'].append({'name': child.type, 'val': child.value, 'line': child.line, 'col': child.column})
        return root