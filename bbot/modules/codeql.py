from bbot.modules.base import BaseModule
from webcap.browser import Browser
from webcap import defaults
import tempfile
import os
import uuid
import csv
import shutil


class codeql(BaseModule):
    watched_events = ["URL"]
    produced_events = ["HTTP_RESPONSE_DOM"]
    flags = ["active"]
    meta = {
        "description": "experimental dom xss module using webcap",
        "created_date": "2025-03-05",
        "author": "@liquidsec",
    }
    deps_pip = ["numpy", "webcap"]

    options = {"ignore_scope": False, "min_severity": "error"}
    options_desc = {
        "ignore_scope": "Ignore scope and process all scripts",
        "min_severity": "Minimum severity level to report (error, warning, recommendation, note)",
    }

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
        {"name": "Make codeql executable", "file": {"path": "#{BBOT_TOOLS}/codeql/codeql", "mode": "u+x,g+x,o+x"}},
        {
            "name": "Install JavaScript query pack",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/javascript-queries",
        },
    ]

    in_scope_only = True
    _module_threads = 4

    async def setup(self):
        self.ignore_scope = self.config.get("ignore_scope", False)
        self.severity_levels = {"error": 4, "warning": 3, "recommendation": 2, "note": 1}

        self.min_severity = self.config.get("min_severity", "error").lower()
        if self.min_severity not in self.severity_levels:
            return (
                False,
                f"Invalid severity level '{self.min_severity}'. Valid options are: {', '.join(self.severity_levels.keys())}",
            )

        # Clean up any stale database files
        database_dir = os.path.join(self.scan.helpers.tools_dir, "codeql", "databases")
        if os.path.exists(database_dir):
            for item in os.listdir(database_dir):
                item_path = os.path.join(database_dir, item)
                if os.path.isfile(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            self.debug(f"Cleaned up stale CodeQL databases in {database_dir}")

        return True

    async def execute_codeql_create_db(self, source_root, database_path):
        command = [
            f"{self.scan.helpers.tools_dir}/codeql/codeql",
            "database",
            "create",
            database_path,
            "--language=javascript",
            f"--source-root={source_root}",
        ]
        self.verbose(f"Executing CodeQL command to create db")
        async for line in self.run_process_live(command):
            pass

    async def execute_codeql_analyze_db(self, database_path):
        # Create a temporary file for the output
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as temp_file:
            output_path = temp_file.name

        command = [
            f"{self.scan.helpers.tools_dir}/codeql/codeql",
            "database",
            "analyze",
            database_path,
            "--format=csv",
            "codeql/javascript-queries:Security/CWE-079/ExceptionXss.ql",
            "codeql/javascript-queries:Security/CWE-079/XssThroughDom.ql",
            "codeql/javascript-queries:Security/CWE-079/StoredXss.ql",
            "codeql/javascript-queries:Security/CWE-079/UnsafeJQueryPlugin.ql",
            "codeql/javascript-queries:Security/CWE-079/UnsafeHtmlConstruction.ql",
            "codeql/javascript-queries:Security/CWE-079/Xss.ql",
            "codeql/javascript-queries:Security/CWE-079/ReflectedXss.ql",
            "codeql/javascript-queries:Security/CWE-601/ClientSideUrlRedirect.ql",
            "codeql/javascript-queries:Security/CWE-201/PostMessageStar.ql",
            "codeql/javascript-queries:Security/CWE-094/CodeInjection.ql",
            "codeql/javascript-queries:Security/CWE-094/ExpressionInjection.ql",
            "codeql/javascript-queries:AngularJS/InsecureUrlWhitelist.ql",
            "codeql/javascript-queries:AngularJS/DisablingSce.ql",
            f"--output={output_path}",
        ]

        self.verbose(f"Executing CodeQL command to analyze db")

        # Run the command and capture the output
        async for line in self.run_process_live(command):
            self.hugeinfo(line)

        # Read and parse the CSV results
        results = []
        with open(output_path, "r") as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if len(row) >= 9:  # Ensure we have all expected fields
                    results.append(
                        {
                            "title": row[0],
                            "full_description": row[1],
                            "severity": row[2],
                            "message": row[3],
                            "file": row[4],
                            "start_line": int(row[5]) if row[5].isdigit() else "N/A",
                            "start_column": int(row[6]) if row[6].isdigit() else "N/A",
                            "end_line": int(row[7]) if row[7].isdigit() else "N/A",
                            "end_column": int(row[8]) if row[8].isdigit() else "N/A",
                        }
                    )

        # Clean up the temporary file
        os.remove(output_path)

        return results

    async def handle_event(self, event):
        findings = set()  # Track unique findings

        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Initialize script_urls dictionary
            script_urls = {}

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

                self.debug(f"DOM file: {dom_file_path} written to temp directory")
                scripts = webscreenshot.scripts
                for i, js in enumerate(scripts):
                    script_url = js.json.get("url", "unknown_url")

                    # Skip out-of-scope scripts if configured
                    if not self.ignore_scope:
                        try:
                            parsed_url = self.helpers.urlparse(script_url)
                            script_domain = parsed_url.netloc
                            if not self.scan.in_scope(script_domain):
                                self.debug(f"Skipping out-of-scope script: {script_url}")
                                continue
                        except Exception as e:
                            self.debug(f"Error parsing script URL {script_url}: {e}")
                            continue

                    loaded_js = js.json["script"]
                    script_urls[i] = script_url
                    js_file_path = os.path.join(temp_dir, f"script_{i}.js")
                    with open(js_file_path, "w") as js_file:
                        js_file.write(loaded_js)
                    self.debug(f"JS file: {js_file_path} written to temp directory. Source: [{script_url}]")

            # Generate a unique GUID for the database
            guid = str(uuid.uuid4())
            database_path = os.path.join(f"{self.helpers.tools_dir}/codeql/databases", guid)
            self.debug(f"Writing database to {database_path}")
            # Run the execute_codeql_create_db method with the temp directory
            await self.execute_codeql_create_db(temp_dir, database_path)

            # Call the execute_codeql_analyze_db method
            results = await self.execute_codeql_analyze_db(database_path)

            # Post-process results and extract code
            for result in results:
                # Extract relevant code portion
                file_path = os.path.join(temp_dir, result["file"].lstrip("/"))
                with open(file_path, "r") as f:
                    lines = f.readlines()

                    # Attempt to extract code snippet if line numbers are valid
                    start_line = result.get("start_line")
                    start_column = result.get("start_column")
                    end_column = result.get("end_column")

                    code_snippet = None
                    if isinstance(start_line, int):
                        start_line -= 1  # Adjust for zero-based index
                        # Get the full line and sanitize for console output
                        full_line = lines[start_line].strip().encode("ascii", "replace").decode()

                        # If line is under 150 chars, use the whole line
                        if len(full_line) <= 150:
                            code_snippet = full_line
                        # Otherwise use the column positions
                        elif all(isinstance(x, int) for x in [start_column, end_column]):
                            start_column -= 1  # Adjust for zero-based index
                            code_snippet = full_line[start_column:end_column]
                        else:
                            # If we can't use columns, truncate with ellipsis
                            code_snippet = full_line[:147] + "..."

                        self.debug(f"Extracted code snippet (line {start_line + 1}):\n{code_snippet}")
                    else:
                        self.debug(f"Could not extract code snippet due to invalid line numbers: {result}")

                    # Skip results that don't meet severity threshold
                    if not self.severity_threshold(result["severity"]):
                        continue

                    # Format the location string based on the file name
                    file_name = result["file"].lstrip("/")
                    if file_name.startswith("script_"):
                        script_num = int(file_name.split("_")[1].split(".")[0])
                        location = script_urls.get(script_num, "unknown_url")
                    elif file_name == "dom.html":
                        location = f"{event.data} (DOM)"
                    else:
                        location = file_name

                    # Add line and column information
                    location_details = f"Line: {start_line + 1}"
                    if isinstance(start_column, int) and isinstance(end_column, int):
                        location_details += f" Cols: {start_column}-{end_column}"

                    # Prepare details string with all the information
                    details_string = f"{result['title']}. Description: [{result['full_description']}] Severity: [{result['severity']}] Location: [{location} ({location_details})] Code Snippet: [{code_snippet}]"

                    # Create a hash of the finding
                    finding_hash = hash(
                        (result["title"], result["full_description"], result["severity"], code_snippet)
                    )

                    if finding_hash in findings:
                        self.debug(f"Skipping duplicate finding: {result['title']} with code snippet: {code_snippet}")
                        continue

                    findings.add(finding_hash)

                    # Prepare data for the event
                    data = {
                        "description": f"POSSIBLE Client-side Vulnerability: {details_string}",
                        "host": str(event.host),
                    }

                    # Emit event with the extracted information
                    await self.emit_event(
                        data,
                        "FINDING",
                        event,
                        context=f"{{module}} module found POSSIBLE Client-side Vulnerability: {details_string}",
                    )

            # Clean up the database directory
            shutil.rmtree(database_path)
            self.debug(f"Cleaned up database directory: {database_path}")

    def severity_threshold(self, severity):
        severity = severity.lower()
        min_level = self.severity_levels.get(self.min_severity, 4)  # Default to error if invalid
        current_level = self.severity_levels.get(severity, 0)  # Default to 0 if unknown severity
        return current_level >= min_level
