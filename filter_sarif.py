#!/usr/bin/env python3
"""
Filter SARIF files based on file, rule and message patterns.

File paths and rule ids are filtered using glob patterns. Message patterns are python regular expressions.
"""

import argparse
import json
import logging
import re
from typing import Any, Dict, Iterable, List, NoReturn, Optional, Tuple
from string import Formatter

from globber import match

LOG = logging.getLogger(__name__)

sepchar = ':'
escchar = '\\'
include_char = '+'
exclude_char = '-'
special_chars = (include_char, exclude_char, escchar, sepchar)


def fail(msg: str) -> NoReturn:
    """Prints an error message and exits with a non-zero exit code."""
    print(msg)
    exit(-1)


def match_patterns(path: Optional[str], rule: Optional[str], message: Optional[str],
                   patterns: Iterable[Tuple[bool, str, Optional[str], Optional[str]]]) -> bool:
    """Match a path, rule and message against a list of patterns."""
    result = True

    LOG.debug("Matching patterns against %s:%s:%s", path, rule, message)

    for sign, file_pattern, rule_pattern, message_pattern in patterns:
        LOG.debug("Matching against %s", (sign, file_pattern, rule_pattern, message_pattern))
        if (path is None or file_pattern is None or
                match(file_pattern, path)) and (rule is None or rule_pattern is None or match(rule_pattern, rule)) and (
                    message_pattern is None or message is None or re.search(message_pattern, message)):
            LOG.debug("Matched")
            result = sign

    return result


def parse_pattern(line: str) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """Parse a pattern line into a tuple of (sign, file_pattern, rule_pattern, message_pattern)."""
    sign = True
    file_pattern: str = ''
    rule_pattern: Optional[str] = None
    message_pattern: Optional[str] = None
    seen_separator: int = 0

    # inclusion or exclusion pattern?
    uline = line
    if line:
        if line[0] == exclude_char:
            sign = False
            uline = line[1:]
        elif line[0] == include_char:
            uline = line[1:]

    # parse patterns character by character
    i = 0
    line_length = len(uline)

    while i < line_length:
        c = uline[i]
        i += 1
        if c == sepchar:
            seen_separator += 1
            if seen_separator > 2:
                raise ValueError(
                    f'Invalid pattern: "{line}" contains more than two separators. Use {escchar}{sepchar} to escape the separator.'
                )
            if seen_separator == 1:
                rule_pattern = ''
            elif seen_separator == 2:
                message_pattern = ''
            continue
        elif c == escchar:
            nextc = uline[i] if (i < line_length) else None
            if nextc in special_chars:
                i += 1
                c = nextc
        if seen_separator == 1:
            rule_pattern = rule_pattern + c if rule_pattern is not None else None
        elif seen_separator == 2:
            message_pattern = message_pattern + c if message_pattern is not None else None
        else:
            file_pattern += c

    return sign, file_pattern, rule_pattern, message_pattern


class SafeFormatter(Formatter):
    """Prevent arbitrary field names - just allow numeric names, for positional arguments, with no formatting instructions."""
    valid_field_name_re = re.compile(r'^[0-9]{1,2}$')

    def get_field(self, field_name: str, args: List[str], kwargs: Dict[str, str]) -> Any:
        if not SafeFormatter.valid_field_name_re.match(field_name):
            raise ValueError('Invalid format string.')
        return super().get_field(field_name, args, kwargs)


def get_message_text(result: Dict[str, Any]) -> Optional[str]:
    """Process result to get message text."""
    message_object = result.get('message', None)
    if message_object is None:
        return None

    message_text: Optional[str] = message_object.get('text', None)
    message_markdown: Optional[str] = message_object.get('markdown', None)
    message_id: Optional[str] = message_object.get('id', None)
    message_arguments: Optional[List[str]] = message_object.get('arguments', None)

    if message_text is not None:
        if message_arguments is None:
            return message_text
        else:
            try:
                form = SafeFormatter()
                return form.format(message_text, *message_arguments)
            except Exception as err:
                LOG.warning("Message arguments malformed: %s", err)
                return message_text
    elif message_markdown is not None:
        return message_markdown
    elif message_id is not None:
        # TODO: get message from rest of results
        LOG.debug("Message id: %s", message_id)
        LOG.warning("Message with id '%s' not processed", message_id)
        return None

    return None


def filter_sarif(args: argparse.Namespace) -> None:
    """Filter SARIF files based on provided patterns."""
    if args.split_lines:
        patterns = []
        for p in args.patterns:
            patterns.extend(re.split('\r?\n', p))
    else:
        patterns = args.patterns

    parsed_patterns = [parse_pattern(p) for p in patterns if p is not None]

    if args.debug:
        LOG.setLevel(logging.DEBUG)

        LOG.debug('Given patterns:')
        for sign, file_pattern, rule_pattern, message_pattern in parsed_patterns:
            LOG.debug(
                f'files: {file_pattern}; rules: {rule_pattern}; messages: {message_pattern} ({"positive" if sign else "negative"})'
            )

    with open(args.input, 'r') as input_file:
        sarif = json.load(input_file)

    if 'runs' in sarif:
        for run in sarif['runs']:
            if 'results' in run:
                new_results = []
                for result in run['results']:
                    message = get_message_text(result)
                    if message is None:
                        LOG.debug("Could not get message text from result.")

                    if 'locations' in result:
                        new_locations = []

                        for location in result['locations']:
                            # TODO: The uri field is optional. We might have to fetch the actual uri from "artifacts" via "index"
                            # (see https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md#-linking-results-to-artifacts)
                            uri = location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', None)

                            # TODO: The ruleId field is optional and potentially ambiguous. We might have to fetch the actual
                            # ruleId from the rule metadata via the ruleIndex field.
                            # (see https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md#rule-metadata)
                            ruleId = result.get('ruleId', None)

                            if match_patterns(uri, ruleId, message, parsed_patterns):
                                new_locations.append(location)
                                # LOG.debug("Location kept: %s", location)

                        if len(new_locations) > 0:
                            result['locations'] = new_locations
                            new_results.append(result)
                            LOG.debug("Result kept: %s", result)
                    else:
                        # locations array doesn't exist or is empty, so we can't match on anything
                        # therefore, we include the result in the output
                        new_results.append(result)
                        LOG.debug("Result kept (with no locations): %s", result)
                run['results'] = new_results

    with open(args.output, 'w') as output_file:
        json.dump(sarif, output_file, indent=2)


def add_args(parser: argparse.ArgumentParser) -> None:
    """Adds arguments to the given parser."""
    parser.add_argument('--input', '-i', help='Input SARIF file', required=True)
    parser.add_argument('--output', '-o', help='Output SARIF file', required=True)
    parser.add_argument('--split-lines',
                        '-s',
                        default=False,
                        action='store_true',
                        help='Split given patterns on newlines (NL or CR/NL).')
    parser.add_argument('patterns', help='Inclusion and exclusion patterns.', nargs='+')
    parser.add_argument('--debug', '-d', help='Debug messages on', action='store_true')


def main() -> None:
    """Main function."""
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(prog='filter-sarif',
                                     description='Filter SARIF files based on file, rule and message patterns.')
    add_args(parser)

    args = parser.parse_args()
    filter_sarif(args)


if __name__ == '__main__':
    main()
