# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/nexB/scancode.io
# The ScanCode.io software is licensed under the Apache License version 2.0.
# Data generated with ScanCode.io is provided as-is without warranties.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. No content created from
# ScanCode.io should be considered or used as legal advice. Consult an Attorney
# for any legal advice.
#
# ScanCode.io is a free software code scanning tool from nexB Inc. and others.
# Visit https://github.com/nexB/scancode.io for support and download.

# isort:skip_file

import django

django.setup()

from commoncode.hash import multi_checksums
from scancode_config import __version__ as scancode_version

from scanpipe.pipes import copy_inputs
from scanpipe.pipes import scancode
from scanpipe.pipelines import Pipeline
from scanpipe.pipelines import step


class ScanPackageArchive(Pipeline):
    """
    A pipeline to scan a single package.
    """

    scancode_options = [
        "--classify",
        "--consolidate",
        "--copyright",
        "--email",
        "--info",
        "--is-license-text",
        "--license",
        "--license-clarity-score",
        "--license-text",
        "--package",
        "--summary",
        "--summary-key-files",
        "--url",
    ]

    @step
    def start(self):
        """
        Load the Project instance.
        """
        self.project = self.get_project(self.project_name)
        self.next(self.validate_and_copy_single_archive_input)

    @step
    def validate_and_copy_single_archive_input(self):
        """
        Ensure that the input for this Pipeline is a single archive.
        Copy the input to the project codebase/ directory.
        """
        input_files = self.project.input_files
        if len(input_files) != 1:
            raise Exception("Only 1 input file supported")

        self.archive_path = self.project.input_path / input_files[0]
        copy_inputs([self.archive_path], self.project.tmp_path)

        self.next(self.collect_archive_information)

    @step
    def collect_archive_information(self):
        """
        Collect archive information and store on project.
        """
        self.project.extra_data.update(
            {
                "filename": self.archive_path.name,
                "size": self.archive_path.stat().st_size,
                **multi_checksums(self.archive_path),
            }
        )
        self.project.save()

        self.next(self.run_extractcode)

    @step
    def run_extractcode(self):
        """
        Extract archive with extractcode.
        """
        scancode.run_extractcode(location=str(self.project.codebase_path))

        self.next(self.run_scancode)

    @step
    def run_scancode(self):
        """
        Scan extracted archive content.
        """
        output_file = self.project.output_path / f"scan_{scancode_version}.json"
        scancode.run_scancode(
            location=str(self.project.codebase_path),
            output_file=output_file,
            options=self.scancode_options,
        )

        self.next(self.collect_key_files_data)

    @step
    def collect_key_files_data(self):
        """
        Collect the key files data.
        """
        # TODO:
        # key_files_data = scan.get_key_files_data()
        # dump_key_files_data(key_files_data, directory, scan.key_files_output_file)
        self.next(self.build_results_summary)

    @step
    def build_results_summary(self):
        """
        Build the summary from the Scan output.
        """
        # TODO:
        # scan.summary = scan.get_summary_from_output()
        self.next(self.end)

    @step
    def end(self):
        """
        Scan completed.
        """


if __name__ == "__main__":
    ScanPackageArchive()
