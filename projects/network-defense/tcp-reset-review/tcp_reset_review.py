"""Review repeated recorded TCP resets in one saved Zeek JSON connection log."""

import argparse
from collections import Counter, defaultdict
from decimal import Decimal, DecimalException
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

MAX_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_RECORDS = 10000
STATES = {'S0', 'S1', 'SF', 'REJ', 'S2', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR', 'OTH'}
RESET_STATES = {
    'RSTO': ('originator', 'established'),
    'RSTR': ('responder', 'unspecified'),
    'RSTOS0': ('originator', 'no_responder_syn_ack_seen'),
    'RSTRH': ('responder', 'no_originator_syn_seen'),
}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('non-finite JSON number')


def _decimal(value):
    try:
        return Decimal(value)
    except DecimalException:
        raise ValueError('JSON decimal is outside the supported range') from None


def _timestamp(value):
    if (type(value) not in (int, Decimal) or not Decimal(value).is_finite() or
            not 0 <= value <= 253402300799 or Decimal(value).as_tuple().exponent < -6):
        raise ValueError('expected finite nonnegative epoch seconds with at most six fractional digits')
    return int(Decimal(value) * 1000000)


def _epoch(microseconds):
    seconds, fraction = divmod(microseconds, 1000000)
    return f'{seconds}.{fraction:06d}'


def _record(raw, line):
    if len(raw) > MAX_LINE_BYTES:
        raise ValueError('connection row exceeds 64 KiB')
    row = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_float=_decimal, parse_constant=_constant)
    required = {'ts', 'uid', 'proto', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'conn_state'}
    if not isinstance(row, dict) or not required <= set(row):
        raise ValueError('missing required Zeek connection fields')
    if not isinstance(row['uid'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', row['uid']):
        raise ValueError('invalid connection UID')
    if (not isinstance(row['proto'], str) or not isinstance(row['conn_state'], str) or
            row['proto'] not in ('tcp', 'udp', 'icmp') or row['conn_state'] not in STATES):
        raise ValueError('unsupported protocol or connection state')
    addresses = []
    for field in ('id.orig_h', 'id.resp_h'):
        value = row[field]
        if not isinstance(value, str) or '%' in value:
            raise ValueError('expected an unscoped IP address')
        addresses.append(ipaddress.ip_address(value).compressed)
    if ipaddress.ip_address(addresses[0]).version != ipaddress.ip_address(addresses[1]).version:
        raise ValueError('connection endpoints must use the same address family')
    for field in ('id.orig_p', 'id.resp_p'):
        if type(row[field]) is not int or not 0 <= row[field] <= 65535:
            raise ValueError('connection ports must be integers from 0 to 65535')
    return {'ts_us': _timestamp(row['ts']), 'uid': row['uid'], 'proto': row['proto'],
            'responder': addresses[1], 'responder_port': row['id.resp_p'], 'state': row['conn_state'],
            'line': line, 'line_sha256': hashlib.sha256(raw).hexdigest()}


def review_bytes(data, *, scope, min_resets=3, window_seconds=60):
    """Return one strongest count window per responder service and reset state."""
    if scope not in ('synthetic', 'owned', 'authorized'):
        raise ValueError('an explicit input scope is required')
    if type(min_resets) is not int or not 2 <= min_resets <= MAX_RECORDS:
        raise ValueError('min_resets must be 2 to 10000')
    if type(window_seconds) is not int or not 1 <= window_seconds <= 86400:
        raise ValueError('window_seconds must be 1 to 86400')
    if not isinstance(data, bytes) or not data or len(data) > MAX_BYTES:
        raise ValueError('expected a nonempty input of at most 8 MiB')
    lines = data.split(b'\n')
    if lines[-1] == b'':
        lines.pop()
    if len(lines) > MAX_RECORDS:
        raise ValueError('connection count exceeds 10000')
    groups, seen, states = defaultdict(list), set(), Counter()
    non_tcp = 0
    for line, raw in enumerate(lines, 1):
        if raw.endswith(b'\r'):
            raw = raw[:-1]
        row = _record(raw, line)
        if row['uid'] in seen:
            raise ValueError('duplicate connection UID; review one sensor export at a time')
        seen.add(row['uid'])
        if row['proto'] != 'tcp':
            non_tcp += 1
            continue
        states[row['state']] += 1
        if row['state'] in RESET_STATES:
            groups[(row['responder'], row['responder_port'], row['state'])].append(row)
    findings = []
    for (address, port, state), rows in sorted(groups.items()):
        rows.sort(key=lambda r: (r['ts_us'], r['uid']))
        left, best_start, best_end = 0, 0, 0
        for right, row in enumerate(rows):
            while row['ts_us'] - rows[left]['ts_us'] > window_seconds * 1000000:
                left += 1
            if right + 1 - left > best_end - best_start:
                best_start, best_end = left, right + 1
        selected = rows[best_start:best_end]
        if len(selected) < min_resets:
            continue
        side, context = RESET_STATES[state]
        findings.append({'kind': 'repeated_recorded_tcp_resets', 'responder_ip': address,
            'responder_port': port, 'conn_state': state, 'reported_reset_side': side,
            'connection_context': context, 'connection_count': len(selected),
            'first_epoch': _epoch(selected[0]['ts_us']), 'last_epoch': _epoch(selected[-1]['ts_us']),
            'evidence': [{'line': r['line'], 'uid': r['uid'], 'line_sha256': r['line_sha256']} for r in selected]})
    return {'schema_version': 1, 'report_type': 'offline-tcp-reset-review', 'scope': scope,
        'input_sha256': hashlib.sha256(data).hexdigest(), 'record_count': len(lines),
        'non_tcp_records': non_tcp, 'tcp_state_counts': dict(sorted(states.items())),
        'parameters': {'min_resets': min_resets, 'window_seconds': window_seconds}, 'findings': findings,
        'limitations': ['Saved Zeek state claims, not authenticated packet evidence or proof of reset injection.',
            'Responder service groups are not attribution to the reset sender or a physical host.',
            'One maximum-count inclusive window per service/state; counts are not rates or a calibrated anomaly score.',
            'REJ is counted separately, not treated as an established reset; partial reset states stay separate.',
            'Legitimate application closes, middleboxes, packet loss and asymmetric visibility can affect interpretation.']}


def _read(path):
    if os.name != 'posix':
        raise ValueError('this bounded file workflow requires POSIX')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError('expected a bounded regular local file')
        data = source.read(MAX_BYTES + 1)
    return data


def _publish(path, text):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.tcp-reset-', delete=False) as output:
            temporary = Path(output.name)
            output.write(text); output.flush(); os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--scope', required=True, choices=('synthetic', 'owned', 'authorized'))
    parser.add_argument('--min-resets', type=int, default=3)
    parser.add_argument('--window-seconds', type=int, default=60)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        report = review_bytes(_read(args.input), scope=args.scope, min_resets=args.min_resets,
                              window_seconds=args.window_seconds)
        rendered = json.dumps(report, sort_keys=True, indent=2) + '\n'
        if args.output:
            _publish(args.output, rendered)
        else:
            print(rendered, end='')
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print('error: saved TCP reset review failed; check local input and review bounds privately', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
