#!/usr/bin/env python3
# -*- mode: python; indent-tabs-mode: nil; python-indent-level: 4 -*-
# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


def load_post_processor():
    toolbox = types.ModuleType("toolbox")
    metrics = types.ModuleType("toolbox.metrics")
    metrics.log_sample = mock.Mock()
    metrics.finish_samples = mock.Mock()
    sys.modules["toolbox"] = toolbox
    sys.modules["toolbox.metrics"] = metrics

    os.environ["TOOLBOX_HOME"] = str(Path(__file__).parents[1])
    path = Path(__file__).parents[1] / "bpftools-post-process.py"
    spec = importlib.util.spec_from_file_location("bpftools_post_process", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, metrics


class DescriptorAggregationTests(unittest.TestCase):
    def test_tcp_window_descriptor_policies(self):
        module, metrics = load_post_processor()
        sample = "1000000000 192.0.2.1 1000 192.0.2.2 2000 10 20 30 40 50\n"

        with tempfile.TemporaryDirectory() as directory:
            previous_directory = os.getcwd()
            os.chdir(directory)
            try:
                Path("bpftrace-boot-epoch-ms.txt").write_text("0\n")
                Path("tcp-window-stdout.txt").write_text(sample)
                module.process_tcp_window("tcp-window-stdout.txt")
            finally:
                os.chdir(previous_directory)

        descriptors = [call.args[1] for call in metrics.log_sample.call_args_list]
        self.assertEqual(len(descriptors), 5)
        self.assertEqual(descriptors[0]["default-aggregation"], "avg")
        srtt = next(desc for desc in descriptors if desc["type"] == "srtt")
        self.assertEqual(srtt["disallowed-aggregations"], ["sum"])
        for desc in descriptors:
            if desc["type"] != "srtt":
                self.assertNotIn("disallowed-aggregations", desc)


if __name__ == "__main__":
    unittest.main()
