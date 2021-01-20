#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
# Copyright (c) 2019 Nicolas Iooss
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Check the order of the entries of the glossary files

This program requires Python>=3.6 for F-strings feature.
"""
from pathlib import Path
import re
import sys


def check_section_sort_order(file_path, sect_lines):
    """Check the sort order of the lines of a section"""
    # Find out lines of sub_sections and analyze them
    result = True
    filtered_lines = []
    subsection_lines = []
    for raw_line in sect_lines:
        line = raw_line.rstrip()
        if line != raw_line:
            print(f"{file_path}: spaces at the end of {repr(raw_line)}")
            result = False

        if line == '':
            if subsection_lines:
                # Add empty lines to subsection
                subsection_lines.append(line)
            # Anyway, add them to the lines in the section too
            filtered_lines.append(line)
        elif line.startswith('  '):
            # Add indented lines to the subsection, without the indent
            subsection_lines.append(line[2:])
        else:
            # non-indented lines means subsections end there
            if subsection_lines:
                if not check_section_sort_order(file_path, subsection_lines):
                    result = False
                subsection_lines = []
            filtered_lines.append(line)

    # Ends recursive structures
    if subsection_lines:
        if not check_section_sort_order(file_path, subsection_lines):
            result = False
    del subsection_lines

    if not filtered_lines:
        return result

    # If there is a dash, every line needs to start with a dash, and this is it
    if any(line.startswith('- ') for line in filtered_lines):
        if not all(not line or line.startswith('- ') for line in filtered_lines):
            print(f"{file_path}: a section with dash needs to have all with dash: {repr(filtered_lines)}")
            result = False
        return result  # Return directly, here

    # Check the sort order of lines starting with a star
    last_sortword = None
    last_sortword_orig = None
    for line in filtered_lines:
        if not line:
            continue
        if not line.startswith('*'):
            # Reset the sort order when a text appears
            if not re.match(r'^[0-9a-zA-Z]', line):
                print(f"{file_path}: unexpected non-list line: {repr(line)}")
                result = False
            last_sortword = None
            last_sortword_orig = None
            continue

        if len(line) < 3 or line[1] != ' ':
            print(f"{file_path}: missing space between */- and words in {repr(line)}")
            result = False
            continue

        # Ignore lists of URLs
        if line.startswith('* https://'):
            if last_sortword is not None:
                print(f"{file_path}: URL while looking for words: {repr(line)}")
                result = False
            continue

        # Find the equal sign
        try:
            eq_idx = line.index('=', 3)
        except ValueError:
            print(f"{file_path}: missing = in {repr(line)}")
            result = False
            continue

        # Keep an "original" unmondified version of the word, in order to display it
        new_word_orig = new_word = line[2:eq_idx].strip()

        new_word = new_word.upper()
        new_word = new_word.replace('/', '')
        new_word = new_word.replace('-', '')
        new_word = new_word.replace('²', '2')

        if last_sortword is not None and last_sortword > new_word:
            print(f"{file_path}: disorder {last_sortword} > {new_word} " +
                  f"({last_sortword_orig} needs to come after {new_word_orig})")
            result = False
        last_sortword = new_word
        last_sortword_orig = new_word_orig

    return result


def check_file_sort_order(file_path):
    """Check the sort order of a file"""
    result = True
    current_lines = []
    title_line = None
    with file_path.open('r', encoding='utf8') as stream:
        for line in stream:
            if not line.endswith('\n'):
                print(f"{file_path}: no \\n at the end of {repr(line)}")
                result = False
            else:
                line = line[:-1]

            if line and not re.match(r'[-0-9a-zA-Z=)/:.~]', line[-1]):
                print(f"{file_path}: unexpected last character in {repr(line)}")
                result = False

            # Detect section headers
            if len(line) >= 3 and all(c == line[0] for c in line):
                try:
                    title_line = current_lines.pop()
                except IndexError:
                    print(f"{file_path}: unexpected title line {repr(line)}")
                    result = False
                else:
                    if len(title_line) != len(line):
                        print(f"{file_path}: the length of the title bar does not match {repr(title_line)}")
                        result = False

                    if current_lines:
                        # Pop the previous empty line
                        if current_lines[-1] != '':
                            print(f"{file_path}: unexpected non-empty line before {repr(title_line)}")
                            result = False
                        else:
                            while current_lines and current_lines[-1] == '':
                                current_lines.pop()

                        # Analyze the section
                        if current_lines:
                            if current_lines[0] == '':
                                current_lines = current_lines[1:]
                            if not check_section_sort_order(file_path, current_lines):
                                result = False
                current_lines = []
                continue

            # Otherwise, stash line into the current lines buffer
            current_lines.append(line)

            # The first line of a section is empty
            if len(current_lines) == 1 and line and title_line is not None:
                print(f"{file_path}: unexpected non-empty line first line in {repr(title_line)}")
                result = False

    return result


def check_sort_order_of_all():
    """Check the sort order of all glossaries"""
    result = True
    base_dir = Path(__file__).parent
    for file_path in base_dir.glob('**/*.rst'):
        if file_path.name != 'README.rst':
            if not check_file_sort_order(file_path):
                result = False
    return result


if __name__ == '__main__':
    sys.exit(0 if check_sort_order_of_all() else 1)
