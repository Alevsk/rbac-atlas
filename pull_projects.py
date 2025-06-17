import os
import subprocess
import yaml
import shutil
import logging
import argparse
from typing import List, Dict, Any, Optional

# --- Configuration Constants ---
DEFAULT_CONFIG_FILE = "projects.yaml"
DEFAULT_OUTPUT_DIR = "charts" # A dedicated directory for pulled charts

# --- Setup Logging ---
# Configure logging to output to console with a specific format
logging.basicConfig(
    level=logging.INFO, # Set default logging level to INFO
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__) # Get a logger for this module

# --- Helper Functions ---

def _run_helm_command(cmd: List[str], capture_output: bool = False) -> Optional[str]:
    """
    Executes a Helm command, logs its execution, and handles errors.

    Args:
        cmd: A list of strings representing the Helm command and its arguments.
        capture_output: If True, captures and returns stdout. Otherwise, prints stdout/stderr directly.

    Returns:
        The captured stdout as a string if capture_output is True, otherwise None.

    Raises:
        subprocess.CalledProcessError: If the command returns a non-zero exit code.
        FileNotFoundError: If the 'helm' executable is not found.
    """
    full_cmd_str = " ".join(cmd)
    logger.info(f"🏃 Running: {full_cmd_str}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True, # Decode stdout/stderr as text
            check=True, # Raise CalledProcessError on non-zero exit code
            encoding='utf-8' # Explicitly set encoding for text output
        )
        if capture_output:
            return result.stdout.strip()
        else:
            # Log stdout/stderr at DEBUG level if not capturing
            if result.stdout:
                logger.debug(f"STDOUT:\n{result.stdout.strip()}")
            if result.stderr:
                logger.debug(f"STDERR:\n{result.stderr.strip()}")
        return None
    except FileNotFoundError:
        logger.critical(f"❌ Error: 'helm' command not found. Please ensure Helm is installed and in your PATH.")
        raise # Re-raise to stop execution if helm isn't found
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Command failed: {full_cmd_str}")
        logger.error(f"Return Code: {e.returncode}")
        if e.stdout:
            logger.error(f"STDOUT:\n{e.stdout.strip()}")
        if e.stderr:
            logger.error(f"STDERR:\n{e.stderr.strip()}")
        raise # Re-raise to allow calling function to handle or for script to terminate
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred while running '{full_cmd_str}': {e}")
        raise

def _get_chart_version_from_folder(chart_folder_path: str) -> str:
    """
    Retrieves the chart version from a local Helm chart folder using 'helm show chart'.

    Args:
        chart_folder_path: The path to the untarred Helm chart folder.

    Returns:
        The version string of the chart.

    Raises:
        ValueError: If the version cannot be found in the chart metadata or if YAML parsing fails.
        subprocess.CalledProcessError: If 'helm show chart' command fails.
    """
    logger.debug(f"Attempting to get chart version from: {chart_folder_path}")
    try:
        chart_yaml_output = _run_helm_command(
            ["helm", "show", "chart", chart_folder_path],
            capture_output=True
        )
        if not chart_yaml_output:
            raise ValueError(f"Helm show chart returned empty output for {chart_folder_path}")

        chart_metadata = yaml.safe_load(chart_yaml_output)
        version = chart_metadata.get("version")
        if not version:
            raise ValueError(f"Version not found in chart metadata for {chart_folder_path}")
        logger.debug(f"Detected version for {chart_folder_path}: {version}")
        return version
    except yaml.YAMLError as e:
        raise ValueError(f"Failed to parse chart YAML for {chart_folder_path}: {e}")
    except subprocess.CalledProcessError:
        # _run_helm_command already logs the error, just re-raise as ValueError for consistency
        raise ValueError(f"Failed to execute 'helm show chart' for {chart_folder_path}")


def _add_helm_repos(repos: List[Dict[str, str]]) -> None:
    """Adds Helm repositories based on the provided configuration."""
    logger.info("Adding Helm repositories...")
    for repo in repos:
        name = repo.get("name")
        url = repo.get("url")
        if not name or not url:
            logger.warning(f"⚠️ Skipping malformed repository entry: {repo}. 'name' and 'url' are required.")
            continue
        try:
            _run_helm_command(["helm", "repo", "add", name, url])
        except subprocess.CalledProcessError:
            logger.warning(f"⚠️ Failed to add repository '{name}' from '{url}'. Continuing with other repos.")
        except Exception as e:
            logger.warning(f"⚠️ An unexpected error occurred while adding repo '{name}': {e}")

def _update_helm_repos() -> None:
    """Updates all added Helm repositories."""
    logger.info("Updating Helm repositories...")
    try:
        _run_helm_command(["helm", "repo", "update"])
    except subprocess.CalledProcessError:
        logger.error("❌ Failed to update Helm repositories. This might affect chart pulling.")
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred during repo update: {e}")

def _get_latest_chart_version(repo_name: str, chart_name: str) -> str:
    """
    Gets the latest version of a chart from the Helm repository.

    Args:
        repo_name: The name of the Helm repository.
        chart_name: The name of the chart.

    Returns:
        The latest version string of the chart.

    Raises:
        ValueError: If the version cannot be determined.
    """
    try:
        # Use helm search repo with --versions to get all versions
        full_chart_ref = f"{repo_name}/{chart_name}"
        search_output = _run_helm_command(
            ["helm", "search", "repo", full_chart_ref, "--output", "yaml"],
            capture_output=True
        )
        if not search_output:
            raise ValueError(f"No versions found for chart {full_chart_ref}")

        search_results = yaml.safe_load(search_output)
        if not search_results or not isinstance(search_results, list) or len(search_results) == 0:
            raise ValueError(f"Invalid search results for chart {full_chart_ref}")

        # The first result should be the latest version
        latest_version = search_results[0].get('version')
        if not latest_version:
            raise ValueError(f"Version not found in search results for {full_chart_ref}")

        return latest_version
    except Exception as e:
        raise ValueError(f"Failed to get latest version for {repo_name}/{chart_name}: {e}")

def _pull_single_chart(repo_name: str, chart_config: Dict[str, Any], output_base_dir: str) -> None:
    """
    Pulls a single Helm chart, untars it, and renames the resulting folder.
    First checks if the desired version is already downloaded.
    Handles cases where the target folder already exists.

    Args:
        repo_name: The name of the Helm repository.
        chart_config: A dictionary containing chart details (name, optional version).
        output_base_dir: The base directory where charts should be pulled into.
    """
    chart_name = chart_config.get("name")
    if not chart_name:
        logger.warning(f"⚠️ Skipping malformed chart entry in repo '{repo_name}': {chart_config}. 'name' is required.")
        return

    version_specified = chart_config.get("version")
    full_chart_ref = f"{repo_name}/{chart_name}"

    # Determine target version - either specified or latest
    try:
        if version_specified:
            target_version = version_specified
        else:
            target_version = _get_latest_chart_version(repo_name, chart_name)
            logger.info(f"Latest version for '{full_chart_ref}' is '{target_version}'")
    except ValueError as e:
        logger.error(f"❌ {str(e)}")
        return

    # Set up paths for temporary and final locations
    temp_chart_dir = os.path.join(output_base_dir, chart_name)  # Temporary location where helm untars
    output_folder_name = f"{chart_name}-{target_version}"  # Final versioned name
    final_chart_path = os.path.join(output_base_dir, output_folder_name)

    # Check if the final target folder already exists before attempting to pull
    if final_chart_path and os.path.exists(final_chart_path):
        logger.info(f"⚠️ Chart '{full_chart_ref}' version '{target_version or 'latest'}' already exists at '{final_chart_path}'. Skipping.")
        return

    # Construct the helm pull command
    pull_cmd = ["helm", "pull", full_chart_ref, "--untar", "--destination", output_base_dir]
    if version_specified:
        pull_cmd.extend(["--version", version_specified])

    try:
        _run_helm_command(pull_cmd)
        logger.info(f"Successfully pulled '{full_chart_ref}' to temporary location '{temp_chart_dir}'.")

        # We already know the version, no need to detect it again
        # Just verify the version matches what we expect
        detected_version = _get_chart_version_from_folder(temp_chart_dir)
        if detected_version != target_version:
            logger.warning(f"⚠️ Pulled chart version '{detected_version}' does not match expected version '{target_version}'")

            # After detecting the version, re-check if the *final* target folder already exists.
            # This handles the case where 'latest' was pulled, but that specific version
            # was already present from a previous run.
            if os.path.exists(final_chart_path):
                logger.info(f"⚠️ Chart '{full_chart_ref}' (detected version '{target_version}') already exists at '{final_chart_path}'. Removing newly pulled temporary chart and skipping.")
                shutil.rmtree(temp_chart_dir) # Clean up the newly pulled temp folder
                # Copy the custom values file to the final chart path if it doesn't exist
                custom_values_path = chart_config.get("values")
                if custom_values_path and os.path.exists(custom_values_path) and final_chart_path:
                    target_values_path = os.path.join(final_chart_path, "custom-values.yaml")
                    if not os.path.exists(target_values_path):
                        try:
                            shutil.copy2(custom_values_path, target_values_path)
                            logger.info(f"Copied custom values from '{custom_values_path}' to '{target_values_path}'")
                        except Exception as e:
                            logger.error(f"❌ Failed to copy custom values file: {e}")
                    else:
                        logger.info(f"Custom values file already exists at '{target_values_path}', skipping copy")
                return

        # Rename the temporary untarred folder to its final, versioned name
        if os.path.exists(temp_chart_dir): # Ensure temp_chart_dir exists before renaming
            logger.info(f"Renaming '{temp_chart_dir}' to '{final_chart_path}'.")
            os.rename(temp_chart_dir, final_chart_path)
            logger.info(f"📦 Saved chart '{full_chart_ref}' version '{target_version}' to '{final_chart_path}'.")

            # If a custom values file path is defined in the chart config, copy it to the final chart path
            custom_values_path = chart_config.get("values")
            if custom_values_path and os.path.exists(custom_values_path) and final_chart_path:
                target_values_path = os.path.join(final_chart_path, "custom-values.yaml")
                try:
                    shutil.copy2(custom_values_path, target_values_path)
                    logger.info(f"Copied custom values from '{custom_values_path}' to '{target_values_path}'")
                except Exception as e:
                    logger.error(f"❌ Failed to copy custom values file: {e}")
        else:
            logger.error(f"❌ Expected temporary chart directory '{temp_chart_dir}' not found after pull for '{full_chart_ref}'. This indicates an issue with the Helm pull or file system.")

    except subprocess.CalledProcessError:
        logger.error(f"❌ Failed to pull chart '{full_chart_ref}' (version: {version_specified or 'latest'}). See previous logs for details.")
        # Clean up temp_chart_dir if it was created but something went wrong
        if os.path.exists(temp_chart_dir):
            shutil.rmtree(temp_chart_dir)
            logger.debug(f"Cleaned up partial pull: {temp_chart_dir}")
    except ValueError as e:
        logger.error(f"❌ Error processing chart '{full_chart_ref}': {e}")
        if os.path.exists(temp_chart_dir):
            shutil.rmtree(temp_chart_dir)
            logger.debug(f"Cleaned up partial pull: {temp_chart_dir}")
    except OSError as e:
        logger.error(f"❌ File system error while processing chart '{full_chart_ref}': {e}")
        if os.path.exists(temp_chart_dir):
            shutil.rmtree(temp_chart_dir)
            logger.debug(f"Cleaned up partial pull: {temp_chart_dir}")
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred while pulling chart '{full_chart_ref}': {e}")
        if os.path.exists(temp_chart_dir):
            shutil.rmtree(temp_chart_dir)
            logger.debug(f"Cleaned up partial pull: {temp_chart_dir}")


def main():
    """
    Main function to parse arguments, load configuration, and orchestrate
    the Helm chart pulling process.
    """
    parser = argparse.ArgumentParser(
        description="Automate pulling Helm charts from a YAML configuration file."
    )
    parser.add_argument(
        "-c", "--config",
        default=DEFAULT_CONFIG_FILE,
        help=f"Path to the YAML configuration file (default: '{DEFAULT_CONFIG_FILE}')."
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to save the untarred Helm charts (default: '{DEFAULT_OUTPUT_DIR}')."
    )
    args = parser.parse_args()

    config_file_path = args.config
    output_base_dir = args.output_dir

    # Ensure the output directory exists
    try:
        os.makedirs(output_base_dir, exist_ok=True)
        logger.info(f"Ensured output directory exists: '{output_base_dir}'")
    except OSError as e:
        logger.critical(f"❌ Critical: Could not create output directory '{output_base_dir}': {e}")
        exit(1) # Exit if we can't even create the output directory

    # Load configuration from YAML file
    config: Dict[str, Any] = {} # Initialize config to an empty dict
    try:
        with open(config_file_path, "r", encoding='utf-8') as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict):
            raise ValueError("YAML configuration root must be a dictionary.")
        logger.info(f"Successfully loaded configuration from '{config_file_path}'.")
    except FileNotFoundError:
        logger.critical(f"❌ Critical: Configuration file not found: '{config_file_path}'.")
        exit(1)
    except yaml.YAMLError as e:
        logger.critical(f"❌ Critical: Error parsing YAML configuration file '{config_file_path}': {e}")
        exit(1)
    except ValueError as e:
        logger.critical(f"❌ Critical: Invalid configuration format in '{config_file_path}': {e}")
        exit(1)
    except Exception as e:
        logger.critical(f"❌ Critical: An unexpected error occurred while loading config: {e}")
        exit(1)

    helm_repos = config.get("helm_repos", [])
    if not isinstance(helm_repos, list):
        logger.critical(f"❌ Critical: 'helm_repos' in config must be a list. Found: {type(helm_repos).__name__}.")
        exit(1)

    # Add all repos
    _add_helm_repos(helm_repos)

    # Update all repos
    _update_helm_repos()

    # Pull all charts
    logger.info("Starting Helm chart pulling process...")
    for repo in helm_repos:
        repo_name = repo.get("name")
        if not repo_name:
            logger.warning(f"⚠️ Skipping repository entry with no 'name': {repo}")
            continue

        charts = repo.get("charts", [])
        if not isinstance(charts, list):
            logger.warning(f"⚠️ Skipping charts for repo '{repo_name}': 'charts' must be a list. Found: {type(charts).__name__}.")
            continue

        for chart_config in charts:
            _pull_single_chart(repo_name, chart_config, output_base_dir)

    logger.info("Helm chart pulling process completed.")

if __name__ == "__main__":
    main()
