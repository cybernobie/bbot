from bbot.modules.base import BaseModule
from webcap.browser import Browser
from webcap import defaults
import tempfile
import os
import uuid
import json
import csv
import shutil


class domxss(BaseModule):
    watched_events = ["URL"]
    produced_events = ["HTTP_RESPONSE_DOM"]
    flags = ["active"]
    meta = {
        "description": "experimental dom xss module using webcap",
        "created_date": "2025-03-05",
        "author": "@liquidsec",
    }
    deps_pip = ["numpy", "webcap"]

    deps_ansible = [
        {
            "name": "Create codeql directory",
            "file": {"path": "#{BBOT_TOOLS}/codeql", "state": "directory", "mode": "0755"},
        },
        {
            "name": "Create databases directory",
            "file": {"path": "#{BBOT_TOOLS}/codeql/databases", "state": "directory", "mode": "0755"},
        },
        {
            "name": "Download codeql",
            "unarchive": {
                "src": "https://github.com/github/codeql-cli-binaries/releases/download/v2.20.6/codeql-linux64.zip",
                "dest": "#{BBOT_TOOLS}/",
                "remote_src": True,
            },
        },
        {
            "name": "Make codeql executable",
            "file": {
                "path": "#{BBOT_TOOLS}/codeql/codeql",
                "mode": "u+x,g+x,o+x"
            }
        },
        {
            "name": "Install JavaScript query pack",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/javascript-queries",
        }
    ]

    async def execute_codeql_create_db(self, source_root, database_path):
        command = [
            f"{self.scan.helpers.tools_dir}/codeql/codeql",
            "database", "create", database_path,
            "--language=javascript",
            f"--source-root={source_root}"
        ]
        async for line in self.run_process_live(command):
            self.hugeinfo(line)

    async def execute_codeql_analyze_db(self, database_path):
        # Create a temporary file for the output
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as temp_file:
            output_path = temp_file.name

        command = [
            f"{self.scan.helpers.tools_dir}/codeql/codeql",
            "database", "analyze", database_path,
            "codeql/javascript-queries@1.5.0",
            "--format=csv",
            f"--output={output_path}"
        ]

        # Run the command and capture the output
        async for line in self.run_process_live(command):
            self.hugeinfo(line)

        # Read the contents of the temporary file
        with open(output_path, "r") as file:
            analysis_results = file.readlines()

        # Initialize an empty list for JSON results
        json_results = []

        # Parse CSV and convert to JSON
        csv_reader = csv.reader(analysis_results)
        for row in csv_reader:
            json_results.append({
                "type": row[0],
                "description": row[1],
                "severity": row[2],
                "details": row[3],
                "file": row[4],
                "start_line": row[5],
                "start_column": row[6],
                "end_line": row[7],
                "end_column": row[8]
            })

        # Log or process the JSON results
        self.critical(f"Analysis results:\n{json.dumps(json_results, indent=2)}")

        # Clean up the temporary file
        os.remove(output_path)

        # Return the JSON results
        return json_results

    async def handle_event(self, event):
        self.critical(event)
        
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Uncomment and modify the following lines to gather DOM and JS files
            b = Browser(
                threads=defaults.threads,
                resolution=defaults.resolution,
                user_agent=defaults.user_agent,
                proxy=None,
                delay=3,
                full_page=False,
                dom=True,
                javascript=True,
                requests=False,
                responses=False,
                base64=False,
                ocr=False,
            )
            await b.start()
            async for url, webscreenshot in b.screenshot_urls([event.data]):
                dom = webscreenshot.dom
                dom_file_path = os.path.join(temp_dir, "dom.html")
                with open(dom_file_path, "w") as dom_file:
                    dom_file.write(dom)

                self.critical(f"DOM file: {dom_file_path} written")
                scripts = webscreenshot.scripts
                for i, js in enumerate(scripts):
                    loaded_js = js.json["script"]
                    js_file_path = os.path.join(temp_dir, f"script_{i}.js")
                    with open(js_file_path, "w") as js_file:
                        js_file.write(loaded_js)

                    self.critical(f"JS file: {js_file_path} written")

            # Generate a unique GUID for the database
            guid = str(uuid.uuid4())
            database_path = os.path.join(f"{self.helpers.tools_dir}/codeql/databases", guid)
            self.critical(f"Database path: {database_path}")
            self.critical("executing codeql to create db")
            # Run the execute_codeql_create_db method with the temp directory
            await self.execute_codeql_create_db(temp_dir, database_path)

            # Call the execute_codeql_analyze_db method
            self.critical("executing codeql to analyze db")
            results = await self.execute_codeql_analyze_db(database_path)
            for result in results:
                self.critical(result)

                details_string = f"Type: {result['type']} Description: {result['description']} Details: {result['details']}"

                data = {
                    "description": f"POSSIBLE Client-side Vulnerability. {details_string}", 
                    "host": str(event.host)
                }
                await self.emit_event(
                    data,
                    "FINDING",
                    event,
                    context=f'{{module}} module found POSSIBLE Client-side Vulnerability: {details_string}',
                )

            # Clean up the database directory
            shutil.rmtree(database_path)
            self.critical(f"Cleaned up database directory: {database_path}")

#            matches = list(set(await self.yara_helper.match(self.compiled_rules, loaded_js)))
#    if matches:
#            self.critical(f'Matches found (script): {matches}')

#    self.critical(f'Matches found (dom): {matches}')
