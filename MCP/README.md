# QRadar Analysis Assistant V1

This MCP server provides a suite of tools for an AI assistant to interact with an IBM QRadar SIEM. The primary goal of this toolset is to streamline common security analysis workflows, allowing the assistant to query offenses, perform deep-dive investigations with AQL, and enrich data with contextual information from the QRadar environment.

This server is built to be lightweight and robust, using only standard Python libraries to ensure maximum compatibility.

## Configuration

Before running the server, ensure the following constants are set correctly within the `server_core.py` script:

*   `QRADAR_API_KEY`: Your generated Authorized Service token from the QRadar Admin panel.
*   `QRADAR_BASE_URL`: The base URL for your QRadar console (e.g., `https://172.190.1.122`).

## Available Tools

The tools are organized into logical groups that reflect a typical analyst's workflow.

### Group 1: Core Threat Management (Offenses)

These tools are for managing and understanding the current threat landscape.

*   `get_active_offenses`: Retrieves a list of offenses. Can be filtered to find specific threats (e.g., by status or magnitude).
*   `get_offense_details`: Fetches all detailed information for a single offense using its unique ID.
*   `update_offense`: Modifies an existing offense. Primarily used to close, assign, or change the status of an offense.

### Group 2: Deep Dive Investigation (AQL Search)

These tools provide the powerful ability to run custom searches against the event and flow database.

*   `start_aql_search`: Initiates an asynchronous search using a provided Ariel Query Language (AQL) string.
*   `get_aql_search_status`: Checks the progress of a previously started AQL search.
*   `get_aql_search_results`: Retrieves the results of a search once its status is "COMPLETED".

### Group 3: Context & Enrichment

These tools are used to gather additional information to understand the significance of events and artifacts.

*   `list_reference_set_contents`: Retrieves and lists all items within a named reference set (QRadar's version of a watchlist).
*   `check_reference_set_for_value`: Efficiently checks if a specific value (like an IP address or username) exists within a reference set without downloading the entire list.
*   `get_asset_information`: Fetches details about a corporate asset (e.g., server owner, location) from the QRadar asset model using a filter.

### Group 4: System Information

This group contains tools for basic system verification.

*   `get_system_servers`: Retrieves a list of all servers (managed hosts) in the QRadar deployment. This is an excellent tool to verify that the API connection is working.

---

## Verification & Testing Status

**Tested tools:**
* server
* aql search