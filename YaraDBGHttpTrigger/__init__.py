import logging
import os

from lark.exceptions import UnexpectedToken, ParseError

from YaraDBGHttpTrigger.ydbg import parser
from .ydbg import *

import azure.functions as func


MAX_FILE_SIZE = 1_000_000
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    if "yarafile" not in req.files:
        return func.HttpResponse(f"Not a valid request")

    yara_rule = req.files["yarafile"]
    filename = yara_rule.filename
    filestream = yara_rule.stream
    filestream.seek(0, os.SEEK_END)
    filesize = filestream.tell()

    if filesize < MAX_FILE_SIZE:
        filestream.seek(0)
        try:
            data = filestream.read().decode('utf_8')
            result = parser.parse(data)
        except UnexpectedToken as exp:
            return func.HttpResponse(f"Unexpected Token (line:{exp.line}, col:{exp.column}):\n{exp.get_context(data)}", status_code=422)
        except ParseError as exp:
            return func.HttpResponse(f"Parse Error (line:{exp.line}, col:{exp.column}):\n{exp.get_context(data)}", status_code=422)
        except UnicodeDecodeError as exp:
            return func.HttpResponse(f"Error reading the yara file (should be a valid utf-8 text file)", status_code=422)

        return func.HttpResponse(f"{result}")
    else:
        return func.HttpResponse(f"File size is too big (Max file size {MAX_FILE_SIZE}).")

