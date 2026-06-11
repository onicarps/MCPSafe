"""Tests for GitHub Actions integration files."""

import os

import yaml


def test_action_yml_valid():
    """action.yml should be valid YAML with correct composite action structure."""
    action_path = os.path.join(os.path.dirname(__file__), "..", "action.yml")
    with open(action_path) as f:
        action = yaml.safe_load(f)

    assert action is not None, "action.yml parsed as None"
    assert "runs" in action, "action.yml missing 'runs' key"
    assert action["runs"]["using"] == "composite", "runs.using should be 'composite'"
    assert "version" in action.get("inputs", {}), "inputs should include 'version'"


def test_ci_yml_valid():
    """ci.yml should be valid YAML with jobs key."""
    ci_path = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "ci.yml")
    with open(ci_path) as f:
        ci = yaml.safe_load(f)

    assert ci is not None, "ci.yml parsed as None"
    assert "jobs" in ci, "ci.yml missing 'jobs' key"
