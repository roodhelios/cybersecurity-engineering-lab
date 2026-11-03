"""Release and replace a synthetic DNS review acceptance before its original expiry."""

import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

from demo_responsibility import fixture
from dns_assignment_lifecycle import LifecycleJournal, create_release
from dns_authorized_handoff import _instant
from dns_responsibility import accept_responsibility, create_acceptance


def exercise():
    report,inputs,options,key=fixture()
    with tempfile.TemporaryDirectory(prefix='dns-voluntary-release-') as name:
        with patch('socket.socket',side_effect=AssertionError('network forbidden')):
            journal=LifecycleJournal.create(Path(name)/'lifecycle.sqlite')
            journal.register(report,*inputs,**options)
            target=accept_responsibility(report,*inputs,**options)
            release=create_release(target,signing_key=key,released_at='2026-10-28T12:02:00Z',expires_at='2026-10-28T12:03:00Z')
            at=_instant('2026-10-28T12:02:00Z')
            policy=dict(acceptance_policy=options['acceptance_policy'],
                expected_acceptance_policy_sha256=options['expected_acceptance_policy_sha256'],now=at)
            journal.release(release,**policy)
            if journal.summary(**policy)['released']!=1: raise ValueError('release not visible')
            replacement=create_acceptance(report,authority_data=options['acceptance_policy'],signing_key=key,
                key_id=target['key_id'],finding_sha256=target['finding_sha256'],team=target['team'],
                accepted_at='2026-10-28T12:02:00Z',expires_at='2026-10-28T12:30:00Z')
            register=dict(options,acceptance=replacement,now=at,expected_predecessor=target['acceptance_sha256'])
            negatives=0
            for operation in (lambda:journal.register(report,*inputs,**dict(options,now=at)),
                              lambda:journal.register(report,*inputs,**register)):
                try: operation()
                except ValueError: negatives+=1
                else: raise ValueError('stale or incomplete successor accepted')
            journal.register(report,*inputs,expected_release_sha256=hashlib.sha256(release).hexdigest(),**register)
            try: journal.release(release,**policy)
            except ValueError: negatives+=1
            else: raise ValueError('old release affected successor')
            summary=journal.summary(**policy)
    return dict(status='dns_assignment_lifecycle_exercise_passed',acceptance_events=summary['event_count'],
        release_events=summary['release_count'],eligible_tasks=summary['eligible_for_reverification'],
        negative_cases_rejected=negatives,native_ed25519=True,
        interpretation='Temporary native SQLite and ephemeral in-memory keys over synthetic evidence. '
        'Voluntary release is not remediation, asset ownership, administrative force transfer or global exclusivity. '
        'No network calls or private-key files. Version-1 journals/checkpoints remain separate.')


def main():
    try: result=exercise()
    except (OSError,ValueError,TypeError,KeyError,sqlite3.DatabaseError):
        print('error: DNS lifecycle exercise failed; inspect fixtures and temporary storage',file=sys.stderr); return 2
    print(json.dumps(result,sort_keys=True)); return 0


if __name__=='__main__': raise SystemExit(main())
