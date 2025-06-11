# Sigma Rule Collector

A Python script to collect Sigma rules from various sources (GitHub repositories, single files, raw text URLs), deduplicate them, and store them in a structured SQLite database and as individual YAML files.

## Features

-   **Multiple Source Types**: Collects from GitHub folders, single YAML files, and pages with multiple rules in raw text format.
-   **Deduplication**: Avoids duplicates by checking rule IDs and content hashes.
-   **Intelligent Versioning**: Automatically creates new versions for rules that share a title but have different detection logic.
-   **Structured Storage**: Stores all rule metadata in a SQLite database for easy querying and analysis.
-   **Local Archive**: Saves a local copy of every unique rule as a `.yml` file.
-   **GitHub API Support**: Can use a GitHub personal access token for higher API rate limits.
-   **Detailed Logging**: Provides real-time console output and a final summary of all operations.

## Prerequisites

-   Python 3.6+
-   `pip` for installing packages

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/RaikyHH/Sigma-Collector.git
    cd Sigma-Collector
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

The script is controlled by a `config.json` file. If the file doesn't exist, an example will be created on the first run.

1.  **Copy the example config:**
    ```bash
    # cp config.example.json config.json
    ```

2.  **Edit `config.json`** to add your desired rule sources.

### Configuration Options

The `config.json` is a list of source objects. Each object has the following keys:

-   `name`: (String) A unique, descriptive name for the source.
-   `url`: (String) The URL to fetch rules from. The format depends on the `type`.
-   `type`: (String) The type of the source. Supported types are:
    -   `github_repo_folder`: For a folder in a GitHub repository. The URL should be the API URL (e.g., `https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows`).
    -   `single_file_yaml`: For a single, raw YAML file URL.
    -   `raw_text_regex`: For a raw text page containing multiple YAML documents separated by a pattern (defaults to `title:`).
-   `enabled`: (Boolean) Set to `true` to process this source, `false` to skip it.
-   `github_token`: (String, Optional) Your GitHub Personal Access Token. Recommended for `github_repo_folder` type to avoid rate limiting.
-   `rule_regex`: (String, Optional) A custom regex for the `raw_text_regex` type to identify and split individual rules.

### Example `config.json`

```json
[
    {
        "name": "SigmaHQ Windows Rules",
        "url": "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows",
        "type": "github_repo_folder",
        "github_token": "ghp_YOUR_TOKEN_HERE",
        "enabled": true
    },
    {
        "name": "Suspicious Forfiles Usage Rule",
        "url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_lolbas_forfiles.yml",
        "type": "single_file_yaml",
        "enabled": true
    },
    {
        "name": "Disabled Example Source",
        "url": "SOME_URL",
        "type": "single_file_yaml",
        "enabled": false
    }
]
```

## Usage

Simply run the script from your terminal:

```bash
python sigma_collector.py
```

The script will ask you to press Enter before it starts processing.


### Docker Usage (Recommended)

Using Docker is the easiest and recommended way to run the application, as it requires no local Python setup and bundles all dependencies.

**Prerequisites:**
-   Docker must be installed on your system.

**Instructions:**

1.  **Create a Data Directory**

    First, create a directory on your computer. This directory will hold your configuration and store all outputs (database and rule files).

    ```bash
    mkdir ~/sigma-collector-data
    ```

2.  **Create your `config.json`**

    Inside the directory you just created (`~/sigma-collector-data`), create a file named `config.json` using the format described in the "Configuration" section of the main README.

3.  **Set Permissions**

    The container runs with a dedicated internal user for security reasons. You must grant this user permission to write to your data directory. Execute the following command:

    ```bash
    chmod 777 -R ~/sigma-collector-data
    ```
    *(This is necessary to allow the container to write the database and rule files into your local folder.)*

4.  **Run the Container**

    Now, run the Docker container with the following command. It will automatically pull the image from the GitHub Container Registry.

    ```bash
    docker run --rm -v ~/sigma-collector-data:/data ghcr.io/raikyhh/sigma-collector:latest
    ```

    -   `--rm`: Automatically removes the container after it finishes.
    -   `-v ~/sigma-collector-data:/data`: Maps your local data directory to the `/data` directory inside the container.

    After the run is complete, the `sigma_rules.db` database and the `sigma_rules_files/` directory will be located inside your `~/sigma-collector-data` folder.

## Output

The script generates the following outputs in the same directory:

-   `sigma_rules.db`: An SQLite database file containing all collected rules and their metadata.
-   `sigma_rules_files/`: A directory containing a local copy of each unique Sigma rule in `.yml` format.

---
