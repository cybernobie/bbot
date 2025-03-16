from pathlib import Path
from bbot.modules.base import BaseModule
from webcap.browser import Browser
from webcap import defaults
import tempfile
import os
import uuid
import csv
import shutil
import time


class codeql(BaseModule):
    watched_events = ["URL"]
    produced_events = ["HTTP_RESPONSE_DOM"]
    flags = ["active"]
    meta = {
        "description": "experimental dom xss module using webcap",
        "created_date": "2025-03-05",
        "author": "@liquidsec",
    }
    deps_pip = ["webcap"]

    options = {"mode": "all", "min_severity": "error"}
    options_desc = {
        "mode": "Script processing mode: 'all' (process all scripts), 'in_scope' (only process in-scope scripts), or 'dom_only' (only process DOM)",
        "min_severity": "Minimum severity level to report (error, warning, recommendation, note)",
    }

    deps_ansible = [
        {
            "name": "Create CodeQL directory",
            "file": {"path": "#{BBOT_TOOLS}/codeql", "state": "directory", "mode": "0755"},
            "register": "codeql_dir_created",
        },
        {
            "name": "Create databases directory",
            "file": {
                "path": "#{BBOT_TOOLS}/codeql/databases",
                "state": "directory",
                "mode": "0755",
            },
            "when": "codeql_dir_created is success",
        },
        {
            "name": "Create packages directory",
            "file": {
                "path": "#{BBOT_TOOLS}/codeql/packages",
                "state": "directory",
                "mode": "0755",
            },
            "when": "codeql_dir_created is success",
        },
        {
            "name": "Download CodeQL CLI",
            "unarchive": {
                "src": "https://github.com/github/codeql-cli-binaries/releases/download/v2.20.6/codeql-linux64.zip",
                "dest": "#{BBOT_TOOLS}/",
                "remote_src": True,
            },
            "register": "codeql_downloaded",
            "when": "codeql_dir_created is success",
        },
        {
            "name": "Make CodeQL executable",
            "file": {"path": "#{BBOT_TOOLS}/codeql/codeql", "mode": "u+x,g+x,o+x"},
            "when": "codeql_downloaded is success",
        },
        {
            "name": "Download JavaScript-all Query Pack to Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/javascript-all --dir=#{BBOT_TOOLS}/codeql/packages --common-caches=#{BBOT_TOOLS}/codeql",
            "register": "query_pack_all_downloaded",
        },
        {
            "name": "Install JavaScript-all Query Pack from Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack install #{BBOT_TOOLS}/codeql/packages/codeql/javascript-all/2.5.0 --no-strict-mode --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "query_pack_all_downloaded is success",
            "register": "query_pack_all_installed",
        },
        {
            "name": "Download suite-helpers Query Pack to Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/suite-helpers --dir=#{BBOT_TOOLS}/codeql/packages --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "query_pack_all_installed is success",
            "register": "suite_helpers_downloaded",
        },
        {
            "name": "Install suite-helpers Query Pack from Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack install #{BBOT_TOOLS}/codeql/packages/codeql/suite-helpers/1.0.18 --no-strict-mode --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "suite_helpers_downloaded is success",
            "register": "suite_helpers_installed",
        },
        {
            "name": "Download typos Query Pack to Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/typos --dir=#{BBOT_TOOLS}/codeql/packages --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "suite_helpers_installed is success",
            "register": "typos_downloaded",
        },
        {
            "name": "Install typos Query Pack from Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack install #{BBOT_TOOLS}/codeql/packages/codeql/typos/1.0.18 --no-strict-mode --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "typos_downloaded is success",
            "register": "typos_installed",
        },
        {
            "name": "Download util Query Pack to Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/util --dir=#{BBOT_TOOLS}/codeql/packages --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "typos_installed is success",
            "register": "util_downloaded",
        },
        {
            "name": "Install util Query Pack from Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack install #{BBOT_TOOLS}/codeql/packages/codeql/util/2.0.5 --no-strict-mode --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "util_downloaded is success",
            "register": "util_installed",
        },
        {
            "name": "Download JavaScript-queries Query Pack to Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack download codeql/javascript-queries --dir=#{BBOT_TOOLS}/codeql/packages --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "util_installed is success",
            "register": "query_pack_downloaded",
        },
        {
            "name": "Install JavaScript-queries Query Pack from Custom Directory",
            "command": "#{BBOT_TOOLS}/codeql/codeql pack install #{BBOT_TOOLS}/codeql/packages/codeql/javascript-queries/1.5.0 --no-strict-mode --common-caches=#{BBOT_TOOLS}/codeql",
            "when": "query_pack_downloaded is success",
        },
        {
            "name": "Create CodeQL custom queries directory",
            "file": {
                "path": "#{BBOT_TOOLS}/codeql/packages/codeql/javascript-queries/1.5.0/custom",
                "state": "directory",
                "mode": "0755",
            },
        },
        {
            "name": "Copy custom queries to CodeQL Custom Query Pack directory",
            "copy": {
                "src": "#{BBOT_WORDLISTS}/codeql_queries/",
                "dest": "#{BBOT_TOOLS}/codeql/packages/codeql/javascript-queries/1.5.0/custom/",
                "remote_src": False,
            },
        },
    ]

    in_scope_only = True
    _module_threads = 2

    yara_rules = r"""
    rule sourcevarassign {
        meta:
            name = "Source to Variable Assignment"
            description = "Variable assignment tainted by user input source"
            confidence = "possible"
        strings:
            $varassign = /var\s+[^=]+=[^;]*(location\.(href|hash|pathname|search)|document\.(URL|documentURI|baseURI))[^;\n]*(;|\n|$)/ nocase
        condition:
            $varassign
    }
    """

    async def setup(self):
        # Compile YARA rules during setup
        self.compiled_yara_rules = self.helpers.yara.compile(source=self.yara_rules)

        self.mode = self.config.get("mode", "in_scope").lower()
        valid_modes = {"all", "in_scope", "dom_only"}
        if self.mode not in valid_modes:
            return False, f"Invalid mode '{self.mode}'. Valid options are: {', '.join(valid_modes)}"

        self.severity_levels = {"error": 4, "warning": 3, "recommendation": 2, "note": 1}
        self.min_severity = self.config.get("min_severity", "error").lower()
        if self.min_severity not in self.severity_levels:
            return (
                False,
                f"Invalid severity level '{self.min_severity}'. Valid options are: {', '.join(self.severity_levels.keys())}",
            )

        self.b = Browser(
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
        await self.b.start()

        # Build the query list during setup
        self.queries = [
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-020/MissingOriginCheck.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-079/ExceptionXss.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-346/CorsMisconfigurationForCredentials.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-079/XssThroughDom.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-079/StoredXss.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-079/UnsafeJQueryPlugin.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-079/UnsafeHtmlConstruction.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-079/Xss.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-079/ReflectedXss.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-601/ClientSideUrlRedirect.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-201/PostMessageStar.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-094/CodeInjection.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/Security/CWE-094/ExpressionInjection.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/AngularJS/InsecureUrlWhitelist.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/AngularJS/DisablingSce.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/custom/dom-xss-jquery-contains.ql",
            f"{self.helpers.tools_dir}/codeql/packages/codeql/javascript-queries/1.5.0/custom/xmlhttprequest-to-eval.ql",
        ]

        # Clean up any stale database files older than 3 days
        database_dir = os.path.join(self.scan.helpers.tools_dir, "codeql", "databases")
        if os.path.exists(database_dir):
            current_time = time.time()
            three_days_in_seconds = 3 * 24 * 60 * 60

            for item in os.listdir(database_dir):
                item_path = os.path.join(database_dir, item)
                # Get the last modification time of the file/directory
                try:
                    mtime = os.path.getmtime(item_path)
                    if (current_time - mtime) > three_days_in_seconds:
                        if os.path.isfile(item_path):
                            os.unlink(item_path)
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                        self.debug(f"Cleaned up stale CodeQL database: {item_path}")
                except Exception as e:
                    self.debug(f"Error checking/removing {item_path}: {e}")

        # Compile YARA rules during setup
        self.compiled_yara_rules = self.helpers.yara.compile(source=self.yara_rules)

        return True

    async def execute_codeql_create_db(self, source_root, database_path):
        command = [
            f"{self.scan.helpers.tools_dir}/codeql/codeql",
            "database",
            "create",
            database_path,
            "--language=javascript",
            f"--common-caches={self.scan.helpers.tools_dir}/codeql/",
            f"--source-root={source_root}",
        ]
        self.verbose("Executing CodeQL command to create db")
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
            f"--common-caches={self.scan.helpers.tools_dir}/codeql",
            f"--additional-packs={self.scan.helpers.tools_dir}/codeql/packages",
            *self.queries,
            f"--output={output_path}",
        ]

        self.verbose("Executing CodeQL command to analyze db")

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

    def format_location(self, file_name, script_urls, event_data):
        """Format the location string based on the file name.

        Args:
            file_name (str): The name of the file being processed
            script_urls (dict): Mapping of script numbers to their URLs
            event_data (str): The event data (typically URL) being processed

        Returns:
            str: Formatted location string
        """
        file_name = file_name.lstrip("/")
        if file_name.startswith("script_"):
            script_num = int(file_name.split("_")[1].split(".")[0])
            script_url = script_urls.get(script_num, "unknown_url")
            return f"(script: {script_url})"
        elif file_name == "dom.html":
            return f"{event_data} (DOM)"
        return file_name

    async def handle_event(self, event):
        findings = set()  # Track unique findings

        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            script_urls = {}

            async for url, webscreenshot in self.b.screenshot_urls([event.data]):
                dom = webscreenshot.dom
                dom_file_path = os.path.join(temp_dir, "dom.html")
                with open(dom_file_path, "w") as dom_file:
                    dom_file.write(dom)

                self.debug(f"DOM file: {dom_file_path} written to temp directory")

                # Only process scripts if not in dom_only mode
                if self.mode != "dom_only":
                    scripts = webscreenshot.scripts
                    for i, js in enumerate(scripts):
                        script_url = js.json.get("url", "unknown_url")

                        # Skip scripts that are from the same URL as the page
                        if script_url == str(event.data):
                            self.debug(f"Skipping script with same URL as page: {script_url}")
                            continue

                        # Skip out-of-scope scripts in in_scope mode
                        if self.mode == "in_scope":
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

            # Scan files with YARA before CodeQL analysis
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, "r") as f:
                        content = f.read()
                        results = await self.helpers.yara.match(self.compiled_yara_rules, content, full_result=True)
                        for result in results:
                            # Get rule metadata and name from the match
                            yara_description = result["meta"].get("description", "")
                            confidence = result["meta"].get("confidence", "")
                            rule_name = result["meta"].get("name", result["rule"])

                            # Build description components
                            description = f"{rule_name}: {yara_description}."

                            if confidence:
                                description += f" Confidence: [{confidence}]"

                            matched_text = result["matched_string"]
                            if len(matched_text) > 150:
                                matched_text = matched_text[:147] + "..."
                            description += f" Matched Text: [{matched_text}]"

                            # Format the location using the same helper function
                            location = self.format_location(os.path.basename(file_path), script_urls, event.data)
                            description += f" Location: [{location}]"

                            await self.emit_event(
                                {
                                    "description": f"POSSIBLE Client-side Vulnerability (YARA Match). {description})",
                                    "host": str(event.host),
                                },
                                "FINDING",
                                event,
                                context=f"{{module}} module found a YARA match for rule '{rule_name}' in {location}",
                            )

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

                    # Format the location string using the new function
                    location = self.format_location(result["file"], script_urls, event.data)

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
