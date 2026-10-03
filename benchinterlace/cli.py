"""Four-command routing; Linux execution is imported only for explicit run."""
import argparse
import os
from pathlib import Path
import sys
from .canonical import canonical_bytes
from .errors import ValidationError
from .report import analyze, verify, render_text, escaped


def exit_code(report):
    if report['inference_status']=='unsupported': return 4
    return 0 if report['inference_status']=='available' else 3


def main(argv=None):
    parser=argparse.ArgumentParser(description='BenchInterlace: freeze a plan, run trusted foreground commands once, analyze and verify. Never put secrets in argv, paths, labels or output.')
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('plan',help='Fingerprint explicit executables/files and draw frozen OS-random orders; never execute')
    p.add_argument('--spec',type=Path,required=True); p.add_argument('--out',type=Path,required=True)
    r=sub.add_parser('run',help='Run only your trusted explicit commands on Linux; not a sandbox')
    r.add_argument('--plan',type=Path,required=True); r.add_argument('--out',type=Path,required=True)
    a=sub.add_parser('analyze',help='Analyze a frozen bundle into a new report directory')
    a.add_argument('bundle',type=Path); a.add_argument('--out',type=Path,required=True)
    v=sub.add_parser('verify',help='Read-only bundle and optional report semantic replay')
    v.add_argument('bundle',type=Path); v.add_argument('--report',type=Path)
    args=parser.parse_args(argv)
    try:
        if args.command=='plan':
            from .plan import publish_plan
            publish_plan(args.spec,args.out)
            print('Plan created. Inspect it before running trusted commands; hashes do not authenticate randomization.')
            return 0
        if args.command=='run':
            from .runner_linux import run_plan
            code=run_plan(args.plan,args.out)
            print('Run finished; inspect evidence with analyze.' if code==0 else 'Run did not return success; retain and analyze available evidence.',file=sys.stdout if code==0 else sys.stderr)
            return code
        if args.command=='analyze':
            bundle=args.bundle.resolve(); out=args.out.resolve()
            if out==bundle or bundle in out.parents: raise ValidationError('invalid_path','Report destination must be outside the input bundle')
            if args.out.exists() or args.out.is_symlink(): raise ValidationError('invalid_path','Report destination already exists')
            report=analyze(args.bundle)
            # Exclusive directory/file creation never overwrites an existing artifact.
            os.mkdir(args.out,0o700)
            os.chmod(args.out,0o700)
            for name,data in [('report.json',canonical_bytes(report)),('report.txt',render_text(report).encode('utf-8'))]:
                if len(data)>1048576: raise ValidationError('resource_limit','Report size limit')
                fd=os.open(args.out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as file: file.write(data)
        else:
            report=verify(args.bundle,args.report)
        print(render_text(report),end='')
        return exit_code(report)
    except ValidationError as error:
        print(escaped(error.code+': '+error.detail),file=sys.stderr)
        if error.code=='invalid_path' or args.command in {'plan','run'} and error.code=='invalid_schema': return 2
        if error.code in {'resource_limit','unsupported_primitive'}: return 4
        return 3
    except FileExistsError:
        print('Output target already exists',file=sys.stderr); return 2
    except OSError as error:
        print(escaped('I/O error: '+str(error)),file=sys.stderr); return 5
    except KeyboardInterrupt:
        print('Interrupted',file=sys.stderr); return 130
