"""Exact descriptive arithmetic and deterministic assumption-qualified reports."""
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from fractions import Fraction
import json
from pathlib import Path
from .analysis_worker import run_exact
from .bundle import read_bundle, Reader, Bundle
from .canonical import parse_json
from .constants import VERSION
from .eligibility import interpret
from .errors import ValidationError
from .schema import validate_report


def fraction(n,d):
    f=Fraction(n,d)
    return {'numerator':f.numerator,'denominator':f.denominator}


def warning_records(plan,n=None):
    p=plan['payload'] if plan else None
    alternative=p['alternative'] if p else 'unknown'
    mode=p['output_check']['mode'] if p else 'unknown'
    warnings=[
        {'code':'assumptions_unverified','text':f'Assumption-qualified calculation. Alternative: {alternative}. Requires genuinely independent fair AB/BA assignment and the global sharp null: every measured slot duration is invariant under every complete assignment history, including direct and carryover effects. This is not a weak mean-null test or a causal mechanism claim.'},
        {'code':'no_complete_provenance','text':'Hashes establish byte consistency, not authentic collection, truthful timing, genuine randomness, independent preregistration, or unchanged undeclared dependencies. Recorded absolute input paths are inert during verification.'},
        {'code':'repeated_attempts_uncontrolled','text':'Unseen discarded plans, seed/order selection, repeated attempts until completion or a favorable result, and selective reporting are not audited or adjusted.'},
        {'code':'selection_not_adjusted','text':'Conditioning on successful completion can be anti-conservative when completion depends on assignment. Counting a failed attempt as no rejection preserves a single-attempt unconditional bound only when complete-data slot outcomes are defined for every assignment. No multiplicity adjustment across workloads, alternatives, sessions, or projects.'},
        {'code':'no_semantic_equivalence_proof','text':f'Output check: {mode}. Matching captured bytes does not prove semantic equivalence. Descriptive mean(B)/mean(A) is an observed ratio, not a confidence interval, true-speedup estimate, regression gate, or equivalence finding.'},
        {'code':'no_microbenchmark_accuracy_claim','text':'Elapsed timing includes launch, scheduling, exit-observation and concurrent capture effects. No sub-millisecond accuracy or cross-hardware reproducibility claim.'},
    ]
    if mode=='none': warnings.append({'code':'output_not_checked','text':'No functional-output correctness check was requested.'})
    if n is not None and n<=5: warnings.append({'code':'small_n_resolution','text':'With at most five pairs, the two-sided 5% level is unattainable. Do not choose more samples after seeing this result. With k nonzero differences, the minimum two-sided p is 2^(1-k) for k>=1; all zeros give p=1.'})
    return warnings


def analyze(path):
    e=interpret(read_bundle(path)); p=e.plan['payload'] if e.plan else None
    report=dict(schema='benchinterlace.report.v1',plan_id=e.plan['plan_id'] if e.plan else None,bundle_sha256=e.bundle_sha256,
        analysis_version=VERSION,evidence_status=e.status,inference_status='withheld',reasons=list(e.reasons),
        warnings=warning_records(e.plan,p['measured_pairs'] if p else None),counts=e.counts,descriptive=None,test=None)
    if e.status=='complete':
        differences=[b-a for a,b in zip(e.a,e.b)]
        result=run_exact(differences,p['alternative'])
        if result['limits']['memory_enforcement']=='structural allocation cap only':
            report['warnings'].append({'code':'structural_memory_cap_only','text':'This platform enforces a structural allocation cap only, with a wall watchdog; an OS address-space ceiling is unavailable.'})
        if result['status']=='unsupported':
            report['inference_status']='unsupported'
            if len(report['reasons'])<100: report['reasons'].append(result['reason'])
        else:
            n=len(e.a); a=sum(e.a); b=sum(e.b)
            report['inference_status']='available'
            report['descriptive']=dict(n=n,sum_a_ns=a,sum_b_ns=b,mean_a_ns=fraction(a,n),mean_b_ns=fraction(b,n),mean_difference_ns=fraction(b-a,n),ratio_b_over_a=fraction(b,a))
            with localcontext() as context:
                context.prec=80
                decimal=(Decimal(result['tail_count'])/Decimal(result['assignment_count'])).quantize(Decimal('0.000000000001'),rounding=ROUND_HALF_EVEN)
            report['test']=dict(method='exact-paired-assignment-v1',alternative=p['alternative'],statistic_sum_difference_ns=sum(differences),tail_count=result['tail_count'],assignment_count=result['assignment_count'],p_decimal=str(decimal))
    validate_report(report)
    return report


def verify(path,report_path=None):
    """Recompute all deterministic fields; never execute any recorded command."""
    recomputed=analyze(path)
    if report_path is not None:
        report_path=Path(report_path)
        scratch=Bundle(); reader=Reader(report_path.parent,scratch)
        raw=reader.read(report_path.name,1048576); reader.stable()
        if raw is None or scratch.problems: raise ValidationError('report_mismatch','Report cannot be safely read')
        try:
            saved=parse_json(raw,1048576,canonical=True); validate_report(saved)
        except (ValidationError,ValueError) as error:
            raise ValidationError('report_mismatch','Invalid report: '+str(error)) from error
        if saved['analysis_version']!=VERSION: raise ValidationError('unsupported_primitive','Unsupported report analysis version')
        if recomputed['inference_status']=='unsupported': raise ValidationError('resource_limit','Unable to recompute inference within current resource limits')
        if saved!=recomputed: raise ValidationError('report_mismatch','Report differs from complete semantic replay')
    return recomputed


def escaped(value):
    return json.dumps(str(value),ensure_ascii=True)[1:-1]


def render_text(report):
    lines=['BenchInterlace: assumption-qualified offline analysis',
           'Evidence: '+report['evidence_status'], 'Inference: '+report['inference_status'],
           'Plan: '+str(report['plan_id'])]
    if report['counts']:
        for phase,c in report['counts'].items():
            lines.append(phase+' slots: '+', '.join(f'{k}={v}' for k,v in c.items()))
    if report['test']:
        t=report['test']; d=report['descriptive']; ratio=d['ratio_b_over_a']; diff=d['mean_difference_ns']
        lines += ['Alternative: '+t['alternative'],f"Exact inclusive tail: {t['tail_count']}/{t['assignment_count']} = {t['p_decimal']}",f"Observed mean(B)/mean(A): {ratio['numerator']}/{ratio['denominator']}",f"Observed mean difference ns: {diff['numerator']}/{diff['denominator']}"]
    else: lines.append('No full-experiment effect summary or p-value is available.')
    for reason in report['reasons']: lines.append('Reason '+reason['code']+(': '+escaped(reason['detail']) if reason.get('detail') else ''))
    for warning in report['warnings']: lines.append('Warning '+warning['code']+': '+escaped(warning['text']))
    return '\n'.join(lines)+'\n'
