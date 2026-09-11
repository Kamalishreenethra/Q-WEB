import pytest
import os
from pathlib import Path
from signchain.research.realworld_runner import RealWorldRunner


def test_realworld_runner_manifest_exists():
    manifest = Path('research/realworld/manifest.json')
    assert manifest.exists()


def test_realworld_runner_execution():
    runner = RealWorldRunner()
    res = runner.run_evaluation()
    assert res['total_cases'] >= 10
    assert res['discovered_count'] == res['total_cases']
    assert res['verified_count'] == res['total_cases']
    assert len(res['graph_summary']['edges']) > 0
    assert len(res['prioritization_order']) > 0


def test_realworld_runner_missing_manifest_raises():
    runner = RealWorldRunner(manifest_path='non_existent_manifest.json')
    with pytest.raises(FileNotFoundError):
        runner.run_evaluation()
