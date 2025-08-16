import os
import subprocess
import yaml
import shutil
import logging
import argparse
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration Constants ---
DEFAULT_CONFIG_FILE = "projects.yaml"
DEFAULT_OUTPUT_DIR = "charts"

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- Helper Functions (Largely Unchanged but with Pathlib integration) ---

def _run_helm_command(cmd: List[str], capture_output: bool = False) -> Optional[str]:
    """Executes a Helm command, logs its execution, and handles errors."""
    full_cmd_str = " ".join(cmd)
    logger.info(f"🏃 Running: {full_cmd_str}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            check=True,
            encoding='utf-8'
        )
        if capture_output:
            return result.stdout.strip()
        return None
    except FileNotFoundError:
        logger.critical("❌ Error: 'helm' command not found. Please ensure Helm is installed and in your PATH.")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Command failed: {full_cmd_str}")
        logger.error(f"Return Code: {e.returncode}")
        if e.stdout:
            logger.error(f"STDOUT:\n{e.stdout.strip()}")
        if e.stderr:
            logger.error(f"STDERR:\n{e.stderr.strip()}")
        raise
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred while running '{full_cmd_str}': {e}")
        raise

# --- OPTIMIZATION: New functions for direct index parsing ---

def _get_helm_cache_dir() -> Path:
    """Finds the Helm repository cache directory."""
    try:
        # Ask helm where its cache is to be robust
        helm_env_output = _run_helm_command(["helm", "env"], capture_output=True)
        for line in helm_env_output.splitlines():
            if line.startswith('HELM_CACHE_HOME='):
                # Format is HELM_CACHE_HOME="<path>"
                cache_path_str = line.split('=')[1].strip('"')
                return Path(cache_path_str) / "repository"
    except Exception:
        logger.warning("⚠️ Could not determine Helm cache path from 'helm env'. Falling back to default.")
        return Path.home() / ".cache" / "helm" / "repository"


def _load_repo_indices(repos: List[Dict[str, str]], helm_cache_dir: Path) -> Dict[str, Any]:
    """
    Parses all repository index.yaml files into an in-memory dictionary.
    This is the core of the performance improvement.
    """
    logger.info("Pre-loading Helm repository indices for fast version lookups...")
    repo_indices = {}
    for repo in repos:
        repo_name = repo.get("name")
        if not repo_name:
            continue

        # Helm saves index files as <repo-name>-index.yaml
        index_file = helm_cache_dir / f"{repo_name}-index.yaml"

        if not index_file.is_file():
            logger.warning(f"⚠️ Index file not found for repo '{repo_name}' at {index_file}. Did 'helm repo update' fail?")
            continue

        try:
            with open(index_file, "r", encoding='utf-8') as f:
                index_data = yaml.safe_load(f)
                # We only care about the 'entries' key which contains chart info
                repo_indices[repo_name] = index_data.get("entries", {})
            logger.debug(f"Successfully loaded index for '{repo_name}'.")
        except (yaml.YAMLError, OSError) as e:
            logger.error(f"❌ Failed to load or parse index for repo '{repo_name}': {e}")

    logger.info("✅ Repository indices loaded.")
    return repo_indices


def _get_latest_version_from_index(chart_name: str, repo_index: Dict[str, Any]) -> str:
    """
    Gets the latest chart version directly from the parsed index data.
    This replaces the slow 'helm search repo' command.
    """
    chart_entries = repo_index.get(chart_name)
    if not chart_entries or not isinstance(chart_entries, list):
        raise ValueError(f"Chart '{chart_name}' not found in the repository index.")

    # The first entry in the list is the latest version as per Helm's index file structure.
    latest_chart = chart_entries[0]
    version = latest_chart.get("version")
    if not version:
        raise ValueError(f"Could not find a version for chart '{chart_name}' in the index.")

    return version

# --- End of Optimization Functions ---


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
            # Add --force-update to ensure the repo is fresh if it exists
            _run_helm_command(["helm", "repo", "add", "--force-update", name, url])
        except subprocess.CalledProcessError:
            logger.warning(f"⚠️ Failed to add repository '{name}' from '{url}'. Continuing.")

def _update_helm_repos() -> None:
    """Updates all added Helm repositories."""
    logger.info("Updating Helm repositories...")
    try:
        _run_helm_command(["helm", "repo", "update"])
    except subprocess.CalledProcessError:
        logger.error("❌ Failed to update Helm repositories. This will prevent version checks.")
        raise # Critical error, script cannot proceed reliably

def _pull_single_chart(repo_name: str, chart_config: Dict[str, Any], output_base_dir: Path, repo_indices: Dict[str, Any]) -> str:
    """
    Pulls a single Helm chart. Determines version from pre-loaded index if not specified.
    Returns the final path of the pulled chart for logging.
    """
    chart_name = chart_config.get("name")
    if not chart_name:
        logger.warning(f"⚠️ Skipping malformed chart entry in repo '{repo_name}': {chart_config}.")
        return ""

    version_specified = chart_config.get("version")
    full_chart_ref = f"{repo_name}/{chart_name}"

    try:
        if version_specified:
            target_version = version_specified
        else:
            repo_index = repo_indices.get(repo_name)
            if not repo_index:
                raise ValueError(f"No index data found for repo '{repo_name}'. Cannot determine latest version.")
            target_version = _get_latest_version_from_index(chart_name, repo_index)
            logger.info(f"Latest version for '{full_chart_ref}' is '{target_version}' (from local index).")

    except ValueError as e:
        logger.error(f"❌ Failed to determine version for {full_chart_ref}: {e}")
        return ""

    sanitized_repo_name = repo_name.replace('/', '_')
    output_folder_name = f"{sanitized_repo_name}__{chart_name}__{target_version}"
    final_chart_path = output_base_dir / output_folder_name
    helm_extracted_dir = output_base_dir / chart_name

    if final_chart_path.exists():
        logger.info(f"✅ Chart '{full_chart_ref}' version '{target_version}' already exists. Skipping pull.")
        return f"Skipped (already exists): {final_chart_path}"

    # Clean up any leftover extracted directory from a previous failed run
    if helm_extracted_dir.exists():
        shutil.rmtree(helm_extracted_dir)

    pull_cmd = ["helm", "pull", full_chart_ref, "--untar", "--destination", str(output_base_dir)]
    # Always specify the version for deterministic pulls
    pull_cmd.extend(["--version", target_version])

    try:
        _run_helm_command(pull_cmd)

        if not helm_extracted_dir.exists():
             raise ValueError(f"Helm pull completed but expected directory '{helm_extracted_dir}' was not created.")

        # Rename to the final versioned folder name
        os.rename(helm_extracted_dir, final_chart_path)
        logger.info(f"📦 Saved chart '{full_chart_ref}' v'{target_version}' to '{final_chart_path}'.")

        custom_values_path_str = chart_config.get("values")
        if custom_values_path_str and Path(custom_values_path_str).exists():
            shutil.copy2(custom_values_path_str, final_chart_path / "custom-values.yaml")
            logger.info(f"Copied custom values to '{final_chart_path / 'custom-values.yaml'}'")

        return f"Successfully pulled: {final_chart_path}"

    except (subprocess.CalledProcessError, ValueError, OSError) as e:
        logger.error(f"❌ Failed processing chart '{full_chart_ref}': {e}")
        # Clean up partial pull
        if helm_extracted_dir.exists():
            shutil.rmtree(helm_extracted_dir)
        return ""

def main():
    """Main function to orchestrate the Helm chart pulling process."""
    parser = argparse.ArgumentParser(description="Automate pulling Helm charts from a YAML configuration file.")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_FILE, help=f"Path to YAML config (default: {DEFAULT_CONFIG_FILE}).")
    parser.add_argument("-o", "--output-dir", default=DEFAULT_OUTPUT_DIR, help=f"Directory for untarred charts (default: {DEFAULT_OUTPUT_DIR}).")
    parser.add_argument("--max-workers", type=int, default=10, help="Max concurrent helm pull operations.")
    args = parser.parse_args()

    config_file_path = Path(args.config)
    output_base_dir = Path(args.output_dir)

    try:
        output_base_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Ensured output directory exists: '{output_base_dir}'")
    except OSError as e:
        logger.critical(f"❌ Could not create output directory '{output_base_dir}': {e}")
        exit(1)

    try:
        with open(config_file_path, "r", encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logger.info(f"Successfully loaded configuration from '{config_file_path}'.")
    except (FileNotFoundError, yaml.YAMLError, Exception) as e:
        logger.critical(f"❌ Critical error loading config file '{config_file_path}': {e}")
        exit(1)

    helm_repos = config.get("helm_repos", [])
    if not isinstance(helm_repos, list):
        logger.critical("❌ 'helm_repos' in config must be a list.")
        exit(1)

    # --- Orchestration ---
    _add_helm_repos(helm_repos)
    _update_helm_repos()

    # OPTIMIZATION: Load all indices into memory at once
    helm_cache_dir = _get_helm_cache_dir()
    repo_indices = _load_repo_indices(helm_repos, helm_cache_dir)

    logger.info(f"Starting concurrent Helm chart pulling (max workers: {args.max_workers})...")

    # OPTIMIZATION: Use a ThreadPoolExecutor to pull charts concurrently
    tasks = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        for repo in helm_repos:
            repo_name = repo.get("name")
            if not repo_name:
                continue

            for chart_config in repo.get("charts", []):
                # Submit the task to the pool
                future = executor.submit(_pull_single_chart, repo_name, chart_config, output_base_dir, repo_indices)
                tasks.append(future)

        # Process results as they complete
        for future in as_completed(tasks):
            try:
                result = future.result()
                # Logging is handled inside the function, so we don't need to log success here
                if not result:
                     logger.warning("A chart pull task failed. See logs above for details.")
            except Exception as e:
                logger.error(f"❌ A chart pull task raised an unexpected exception: {e}")

    logger.info("✅ Helm chart pulling process completed.")

if __name__ == "__main__":
    main()
