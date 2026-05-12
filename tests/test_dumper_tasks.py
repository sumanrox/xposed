"""Tests for dumper threading and task processing."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from modules.dumper import Worker, processTasks


class DummyWorker(Worker):
    """Worker that doubles a number and returns new tasks."""
    def init(self, multiplier):
        self.multiplier = multiplier

    def doTask(self, task, multiplier):
        return [task * multiplier]


class TestProcessTasks:
    """processTasks should work with threading-based workers."""

    def test_processes_tasks_recursively(self):
        # Start with 1, double it 3 times: 1 -> 2 -> 4 -> 8
        # Stop when we see a duplicate to avoid infinite loop
        results = set()

        class CollectWorker(Worker):
            def init(self):
                pass

            def doTask(self, task):
                results.add(task)
                if task < 8:
                    return [task * 2]
                return []

        processTasks([1], CollectWorker, jobs=2)
        assert results == {1, 2, 4, 8}

    def test_processes_with_multiple_workers(self):
        class AddWorker(Worker):
            def init(self):
                pass

            def doTask(self, task):
                return [task + 1]

        seen = set()

        class TrackedWorker(Worker):
            def init(self):
                pass

            def doTask(self, task):
                seen.add(task)
                if task < 3:
                    return [task + 1]
                return []

        processTasks([0], TrackedWorker, jobs=4)
        assert seen == {0, 1, 2, 3}

    def test_empty_initial_tasks_returns_immediately(self):
        class NoOpWorker(Worker):
            def init(self):
                pass

            def doTask(self, task):
                return []

        # Should not raise or hang
        processTasks([], NoOpWorker, jobs=2)
