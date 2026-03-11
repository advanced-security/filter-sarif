import sys
import argparse
import json
import re
from globber import match


def fail(msg):
    print(msg)
    sys.exit(-1)


def match_path_and_rule(path, rule, patterns):
    result = True
    for s, fp, rp in patterns:
        if match(rp, rule) and match(fp, path):
            result = s
    return result


def parse_pattern(line):
    sepchar = ':'
    escchar = '\\'
    file_pattern = ''
    rule_pattern = ''
    seen_separator = False
    sign = True

    # inclusion or exclusion pattern?
    uline = line
    if line:
        if line[0] == '-':
            sign = False
            uline = line[1:]
        elif line[0] == '+':
            uline = line[1:]

    i = 0
    while i < len(uline):
        c = uline[i]
        i = i + 1
        if c == sepchar:
            if seen_separator:
                raise Exception('Invalid pattern: "' + line + '" Contains more than one separator!')
            seen_separator = True
            continue
        elif c == escchar:
            nextc = uline[i] if (i < len(uline)) else None
            if nextc in ['+' , '-', escchar, sepchar]:
                i = i + 1
                c = nextc
        if seen_separator:
            rule_pattern = rule_pattern + c
        else:
            file_pattern = file_pattern + c

    if not rule_pattern:
        rule_pattern = '**'

    return sign, file_pattern, rule_pattern


VALID_SARIF_LEVELS = {'error', 'warning', 'note', 'none'}
VALID_SECURITY_CATEGORIES = {'critical', 'high', 'medium', 'low'}
VALID_SEVERITY_VALUES = VALID_SARIF_LEVELS | VALID_SECURITY_CATEGORIES


def compute_security_severity_category(raw_score):
    """Convert a numeric security-severity score string to a named category."""
    try:
        numeric = float(raw_score)
    except (TypeError, ValueError):
        return None
    if numeric >= 9.0:
        return 'critical'
    if numeric >= 7.0:
        return 'high'
    if numeric >= 4.0:
        return 'medium'
    if numeric > 0.0:
        return 'low'
    return None


def collect_rule_severities(run):
    '''Create lookups from ruleId/ruleIndex to security-severity category and default level.'''
    sec_sev_lookup = {}
    default_level_lookup = {}

    def _process_rules(rules, source_name):
        for idx, rule_def in enumerate(rules):
            rid = rule_def.get('id', '')
            sec_sev = rule_def.get('properties', {}).get('security-severity')
            cat = compute_security_severity_category(sec_sev)
            if rid:
                sec_sev_lookup[rid] = cat
            def_level = rule_def.get('defaultConfiguration', {}).get('level')
            if def_level and rid:
                default_level_lookup[rid] = def_level.lower()

    # Process driver rules
    driver_rules = run.get('tool', {}).get('driver', {}).get('rules', [])
    _process_rules(driver_rules, 'driver')

    # Process extension rules (e.g. CodeQL query packs)
    extensions = run.get('tool', {}).get('extensions', [])
    for ext in extensions:
        ext_name = ext.get('name', '?')
        _process_rules(ext.get('rules', []), ext_name)

    return sec_sev_lookup, default_level_lookup


def result_matches_severity(result, allowed_levels, rule_sev_lookup, rule_default_level_lookup):
    """Return True if a result's severity is in the allowed set."""
    # Check standard SARIF result.level (error, warning, note, none).
    # Per SARIF spec, missing/empty level defaults to the rule's defaultConfiguration.level,
    # or "warning" if that is also absent.
    res_level = result.get('level') or None
    if res_level is None:
        rid = result.get('ruleId', '')
        r_idx = result.get('ruleIndex')
        res_level = rule_default_level_lookup.get(rid)
        if res_level is None:
            res_level = rule_default_level_lookup.get(r_idx)
        if res_level is None:
            res_level = 'warning'
    if res_level.lower() in allowed_levels:
        return True

    # Check security-severity category derived from rule metadata
    rid = result.get('ruleId', '')
    r_idx = result.get('ruleIndex')
    sev_cat = rule_sev_lookup.get(rid) or rule_sev_lookup.get(r_idx)
    if sev_cat and sev_cat in allowed_levels:
        return True

    return False


def filter_sarif(args):
    if args.split_lines:
        tmp = []
        for p in args.patterns:
            tmp = tmp + re.split('\r?\n', p)
        args.patterns = tmp

    args.patterns = [parse_pattern(p) for p in args.patterns if p]

    severity_filter = None
    if args.severity:
        severity_filter = set()
        for tok in args.severity.split(','):
            stripped = tok.strip().lower()
            if not stripped:
                continue
            if stripped not in VALID_SEVERITY_VALUES:
                fail('Unknown severity value: "{}". Valid values are: {}'.format(
                    stripped, ', '.join(sorted(VALID_SEVERITY_VALUES))))
            severity_filter.add(stripped)
        print('Severity filter: keeping results with severity in {}'.format(
            ', '.join(sorted(severity_filter))))

    print('Given patterns:')
    for s, fp, rp in args.patterns:
        print(
            'files: {file_pattern}    rules: {rule_pattern} ({sign})'.format(
                file_pattern=fp,
                rule_pattern=rp,
                sign='positive' if s else 'negative'
            )
        )

    with open(args.input, 'r', encoding='utf-8') as f:
        s = json.load(f)

    for run in s.get('runs', []):
        rule_sev_lookup, rule_default_level_lookup = collect_rule_severities(run) if severity_filter else ({}, {})

        if run.get('results', []):
            new_results = []
            for r in run['results']:
                # Apply severity filter if specified
                if severity_filter and not result_matches_severity(r, severity_filter, rule_sev_lookup, rule_default_level_lookup):
                    continue

                if r.get('locations', []):
                    new_locations = []
                    for l in r['locations']:
                        # TODO: The uri field is optional. We might have to fetch the actual uri from "artifacts" via "index"
                        # (see https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md#-linking-results-to-artifacts)
                        uri = l.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', None)
                        # TODO: The ruleId field is optional and potentially ambiguous. We might have to fetch the actual
                        # ruleId from the rule metadata via the ruleIndex field.
                        # (see https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md#rule-metadata)
                        ruleId = r['ruleId']
                        if uri is None or match_path_and_rule(uri, ruleId, args.patterns):
                            new_locations.append(l)
                    r['locations'] = new_locations
                    if new_locations:
                        new_results.append(r)
                else:
                    # locations array doesn't exist or is empty, so we can't match on anything
                    # therefore, we include the result in the output
                    new_results.append(r)
            run['results'] = new_results

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(s, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        prog='filter-sarif'
    )
    parser.add_argument(
        '--input',
        help='Input SARIF file',
        required=True
    )
    parser.add_argument(
        '--output',
        help='Output SARIF file',
        required=True
    )
    parser.add_argument(
        '--split-lines',
        default=False,
        action='store_true',
        help='Split given patterns on newlines.'
    )
    parser.add_argument(
        '--severity',
        default=None,
        help='Comma-separated list of severity levels to keep (e.g. "error,warning" or "high,critical").'
    )
    parser.add_argument(
        'patterns',
        help='Inclusion and exclusion patterns.',
        nargs='+'
    )

    def print_usage(args):
        print(parser.format_usage())

    args = parser.parse_args()
    filter_sarif(args)


main()
