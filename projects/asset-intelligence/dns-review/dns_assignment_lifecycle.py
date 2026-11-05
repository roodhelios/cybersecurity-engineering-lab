"""Version-2 local DNS task journals with explicit voluntary signed release."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

from dns_assignment_journal import AssignmentJournal, SCHEMA, MAX_EVENTS, _now, _policy, _receipt, _state
from dns_assignment_journal import main as journal_main
from dns_authorized_handoff import _crypto, _decode, _instant
from dns_responsibility import accept_responsibility
from dns_review import _fields, _load, _version, read_input
from dns_reviewer_handoff import _digest
from zeek_dns_workflow_verify import _canonical

DOMAIN = b'cybersecurity-engineering-lab:dns-review-voluntary-release:v1\x00'
FIELDS = {'schema_version','action','key_id','audience','finding_sha256','team','workflow_sha256',
          'acceptance_sha256','authority_policy_sha256','released_at','expires_at','signature_b64'}
RELEASE_SCHEMA = """
CREATE TABLE release_event(
 sequence INTEGER PRIMARY KEY,
 acceptance_sha256 TEXT NOT NULL UNIQUE,
 release_sha256 TEXT NOT NULL UNIQUE,
 receipt_json TEXT NOT NULL
);
CREATE TRIGGER release_no_update BEFORE UPDATE ON release_event
 BEGIN SELECT RAISE(ABORT,'journal is append-only'); END;
CREATE TRIGGER release_no_delete BEFORE DELETE ON release_event
 BEGIN SELECT RAISE(ABORT,'journal is append-only'); END;
"""


def _message(claim):
    return DOMAIN+_canonical({k:v for k,v in claim.items() if k!='signature_b64'}).encode('ascii')


def create_release(receipt, *, signing_key, released_at, expires_at):
    """Sign an exact retained target in memory; the receiver checks current authority/state."""
    _receipt(receipt)
    claim = dict(schema_version=1,action='release-dns-review-responsibility',
        **{k:receipt[k] for k in ('key_id','audience','finding_sha256','team','workflow_sha256','acceptance_sha256')},
        authority_policy_sha256=receipt['acceptance_policy_sha256'],released_at=released_at,expires_at=expires_at)
    _instant(released_at); _instant(expires_at)
    claim['signature_b64']=base64.b64encode(signing_key.sign(_message(claim)).signature).decode('ascii')
    return (_canonical(claim)+'\n').encode('ascii')


def _verify(claim, target, policy, pin, now):
    _fields(claim,FIELDS); _version(claim['schema_version'])
    if claim['action']!='release-dns-review-responsibility' or claim['authority_policy_sha256']!=pin:
        raise ValueError('unsupported release purpose or authority')
    for field in ('key_id','audience','finding_sha256','team','workflow_sha256','acceptance_sha256'):
        if claim[field]!=target[field]: raise ValueError('release target differs from current acceptance')
    if _state(target,policy=policy,pin=pin,now=now)!='eligible_for_reverification':
        raise ValueError('only a current active acceptance may be released')
    released, expires = _instant(claim['released_at']),_instant(claim['expires_at'])
    if (not _receipt(target)<=released<=now<expires<=_instant(target['expires_at']) or
            not 0<(expires-released).total_seconds()<=policy['maximum_validity_seconds']):
        raise ValueError('release is outside its validity interval')
    key = next(k for k in policy['keys'] if k['key_id']==target['key_id'])
    VerifyKey,BadSignatureError = _crypto()
    try: VerifyKey(_decode(key['public_key_b64'],32)).verify(_message(claim),_decode(claim['signature_b64'],64))
    except BadSignatureError: raise ValueError('release signature did not verify') from None


class LifecycleJournal(AssignmentJournal):
    VERSION = 2
    SQL = SCHEMA.replace('PRAGMA user_version=1;','PRAGMA user_version=2;')+RELEASE_SCHEMA

    @staticmethod
    def _releases(connection, rows):
        schema=connection.execute("SELECT type,sql FROM sqlite_schema WHERE name='release_event'").fetchall()
        columns=tuple(row[1] for row in connection.execute('PRAGMA table_info(release_event)'))
        if (len(schema)!=1 or schema[0][0]!='table' or not schema[0][1].lstrip().upper().startswith('CREATE TABLE ') or
                columns!=('sequence','acceptance_sha256','release_sha256','receipt_json')):
            raise ValueError('unsupported release table')
        targets={row[3]:_load(row[5].encode()) for row in rows}
        releases=connection.execute('SELECT sequence,acceptance_sha256,release_sha256,receipt_json FROM release_event ORDER BY sequence').fetchmany(MAX_EVENTS+1)
        if len(releases)>MAX_EVENTS: raise ValueError('release event limit exceeded')
        result={}
        fields=(FIELDS-{'signature_b64','action','schema_version'})|{'schema_version','receipt_type','verified_at','release_sha256'}
        for sequence,(number,target,digest,raw) in enumerate(releases,1):
            if number!=sequence or not isinstance(raw,str) or len(raw.encode())>8192: raise ValueError('invalid release event')
            item=_load(raw.encode()); _fields(item,fields); _version(item['schema_version']); _digest(digest)
            acceptance=targets.get(target)
            if (item['receipt_type']!='dns-review-voluntary-release' or acceptance is None or target in result or
                    item['acceptance_sha256']!=target or item['release_sha256']!=digest or
                    any(item[k]!=acceptance[k] for k in ('key_id','audience','finding_sha256','team','workflow_sha256')) or
                    item['authority_policy_sha256']!=acceptance['acceptance_policy_sha256']):
                raise ValueError('invalid release linkage')
            verified=_now(datetime.fromisoformat(item['verified_at']))
            if not _receipt(acceptance)<=_instant(item['released_at'])<=verified<_instant(item['expires_at'])<=_instant(acceptance['expires_at']):
                raise ValueError('invalid retained release time')
            result[target]=item
        return result

    def register(self,report,previous,current,scope,review_policy,*,expected_predecessor=None,expected_release_sha256=None,**options):
        for digest in (expected_predecessor,expected_release_sha256):
            if digest is not None: _digest(digest)
        receipt=accept_responsibility(report,previous,current,scope,review_policy,**options)
        now=_receipt(receipt); pin=options['expected_acceptance_policy_sha256']; policy=_policy(options['acceptance_policy'],pin)
        with self._connection(write=True) as connection:
            rows,latest=self._history(connection); releases=self._releases(connection,rows)
            prior=latest.get((receipt['audience'],receipt['finding_sha256']))
            if prior is not None and now<_receipt(prior): raise ValueError('journal clock moved backwards')
            predecessor=prior['acceptance_sha256'] if prior else None; release=releases.get(predecessor)
            if release is not None and now<_now(datetime.fromisoformat(release['verified_at'])):
                raise ValueError('clock precedes retained release')
            if predecessor==receipt['acceptance_sha256']:
                if release is not None: raise ValueError('released acceptance cannot reactivate')
                return dict(status='already_registered',event_count=len(rows),appended=False)
            if release is not None and _instant(receipt['accepted_at'])<_now(datetime.fromisoformat(release['verified_at'])):
                raise ValueError('replacement acceptance predates release')
            if predecessor!=expected_predecessor or (release['release_sha256'] if release else None)!=expected_release_sha256:
                raise ValueError('explicit lifecycle predecessor differs')
            if prior is not None and release is None and _state(prior,policy=policy,pin=pin,now=now)=='eligible_for_reverification':
                raise ValueError('competing unexpired acceptance')
            if len(rows)>=MAX_EVENTS: raise ValueError('acceptance event limit exceeded')
            connection.execute('INSERT INTO acceptance_event VALUES(?,?,?,?,?,?)',
                (len(rows)+1,receipt['audience'],receipt['finding_sha256'],receipt['acceptance_sha256'],predecessor,_canonical(receipt)))
        return dict(status='review_acceptance_registered',event_count=len(rows)+1,appended=True)

    def release(self,data,*,acceptance_policy,expected_acceptance_policy_sha256,now):
        now=_now(now); pin=expected_acceptance_policy_sha256; policy=_policy(acceptance_policy,pin)
        claim=_load(data); _fields(claim,FIELDS); _digest(claim['acceptance_sha256'])
        with self._connection(write=True) as connection:
            rows,latest=self._history(connection); releases=self._releases(connection,rows)
            target=latest.get((claim['audience'],claim['finding_sha256']))
            if target is None: raise ValueError('no current acceptance')
            _verify(claim,target,policy,pin,now)
            digest=hashlib.sha256(data).hexdigest(); previous_release=releases.get(target['acceptance_sha256'])
            if previous_release is not None:
                if now<_now(datetime.fromisoformat(previous_release['verified_at'])) or digest!=previous_release['release_sha256']:
                    raise ValueError('different release already retained')
                return dict(status='already_released',release_count=len(releases),appended=False)
            if len(releases)>=MAX_EVENTS: raise ValueError('release event limit exceeded')
            receipt={k:v for k,v in claim.items() if k not in ('signature_b64','action')}
            receipt.update(receipt_type='dns-review-voluntary-release',verified_at=now.isoformat(),release_sha256=digest)
            connection.execute('INSERT INTO release_event VALUES(?,?,?,?)',
                (len(releases)+1,target['acceptance_sha256'],digest,_canonical(receipt)))
        return dict(status='review_responsibility_released',release_count=len(releases)+1,appended=True)

    def summary(self,*,acceptance_policy,expected_acceptance_policy_sha256,now):
        now=_now(now); pin=expected_acceptance_policy_sha256; policy=_policy(acceptance_policy,pin)
        with self._connection() as connection:
            rows,latest=self._history(connection); releases=self._releases(connection,rows)
        counts=dict(eligible_for_reverification=0,expired=0,policy_replaced=0,authority_inactive=0,released=0)
        for receipt in latest.values():
            release=releases.get(receipt['acceptance_sha256'])
            if now<_receipt(receipt) or release and now<_now(datetime.fromisoformat(release['verified_at'])):
                raise ValueError('journal clock moved backwards')
            counts['released' if release else _state(receipt,policy=policy,pin=pin,now=now)]+=1
        return dict(status='local_assignment_lifecycle_summary',event_count=len(rows),release_count=len(releases),task_count=len(latest),**counts)


def main(argv=None, *, journal_type=LifecycleJournal):
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv in (['--help'],['-h']):
        parser=argparse.ArgumentParser(description=__doc__,epilog='Use COMMAND --help for its arguments. Version-1 stores are not migrated.')
        parser.add_argument('command',choices=('init','register','release','summary'))
        parser.parse_args(argv)
    if not argv or argv[0]!='release': return journal_main(argv,journal_type=journal_type)
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('command',choices=('release',))
    parser.add_argument('journal',type=Path); parser.add_argument('--release',required=True,type=Path)
    parser.add_argument('--acceptance-policy',required=True,type=Path); parser.add_argument('--expected-acceptance-policy-sha256',required=True)
    parser.add_argument('--at',help='explicit UTC fixture instant; omit for current UTC')
    if journal_type.VERSION == 3:
        parser.add_argument('--enrollment',required=True,type=Path)
        parser.add_argument('--expected-enrollment-sha256',required=True)
    args=parser.parse_args(argv)
    try:
        journal=(journal_type.from_enrollment(args.journal,read_input(args.enrollment),
                 expected_sha256=args.expected_enrollment_sha256) if journal_type.VERSION == 3 else journal_type(args.journal))
        result=journal.release(read_input(args.release),acceptance_policy=read_input(args.acceptance_policy),
            expected_acceptance_policy_sha256=args.expected_acceptance_policy_sha256,now=_instant(args.at) if args.at else datetime.now(timezone.utc))
        result['verification_time_source']='explicit_fixture' if args.at else 'current_utc_clock'
    except (OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,sqlite3.DatabaseError,RecursionError,OverflowError):
        print('error: voluntary DNS release failed; inspect private journal, signature, policy and clock',file=sys.stderr); return 2
    print(json.dumps(result,sort_keys=True)); return 0


if __name__=='__main__': raise SystemExit(main())
