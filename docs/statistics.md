# Statistical contract

For n preplanned measured pairs, let A_i and B_i be positive integer elapsed nanoseconds and d_i=B_i−A_i. The observed statistic is T=sum(d_i). The reference multiset contains S=sum(s_i*d_i) for all independent s_i in {−1,+1}; it has exactly 2^n entries including multiplicities from zeros and ties.

- B-slower: count(S >= T)/2^n
- two-sided: count(abs(S) >= abs(T))/2^n

Ties are inclusive. There is no mid-p, Monte Carlo, asymptotic, plus-one or floating-point-tolerance adjustment. For two-sided T=0, p=1. For one-sided T=0, p=(1+Pr[S=0])/2, not generally 1. For (1,−1), the upper tail is 3/4. The exact counts are authoritative; the decimal is fixed to twelve fractional digits with round-half-even.

The assignment model requires independent fair AB/BA choices fixed before observation. Warmup count/order are fixed outside the measured statistic. The null is global and sharp: every measured time-slot duration is invariant under every possible complete measured assignment vector. It excludes direct and carryover assignment effects on caches, thermal state, scheduling or later slots. It is stronger than equality of means and is not a composite no-slowdown hypothesis. Arbitrary fixed exogenous slot trends remain compatible with it. No independence or normality of observed durations is asserted.

Under that model, ranking all assignments by T or abs(T) with inclusive upper tails gives at most a rejections at each threshold a/2^n. Ties are conservative. If complete-data outcomes exist for all assignments, treating an ineligible/aborted predeclared attempt as no rejection cannot increase this unconditional single-attempt bound. This does not establish validity conditional on completion: retaining only rejecting assignments can make the conditional rejection rate one. When failed outcomes are undefined the extension is not asserted.

The tool does not adjust for unseen attempts, alternative/workload/session choice, plan preview/redraw, or publication selection. It never removes outliers, repairs pairs, retries observations or pools experiments. n<=5 cannot attain a two-sided 5% level. With k>=1 nonzero differences, the smallest possible two-sided p is 2^(1−k). Do not change sample size after seeing a result.

The MITM implementation stores and sorts all right-half integer sums, preserving duplicates, and streams left-half sums. For right list R of length m and left sum l, the upper count is m−bisect_left(R,T−l). For h=abs(T)>0 the two-sided count is bisect_right(R,−h−l)+m−bisect_left(R,h−l); h=0 is handled separately. Python integers preserve exact comparisons and sums. The pure kernel's large-integer tests intentionally exceed the stricter evidence-duration limits.

Descriptive ratio is sum(B)/sum(A), equivalently mean(B)/mean(A), not the mean of pairwise ratios. Means and ratios are reduced exact fractions. They describe these observations, with no confidence interval, practical regression boundary or causal-mechanism conclusion.

References: [SciPy paired-sample permutation documentation](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.permutation_test.html), [Wu and Ding on sharp and weak nulls](https://arxiv.org/abs/1809.07419), [Rosenbaum and Silber matched pairs, section 2.2](https://pmc.ncbi.nlm.nih.gov/articles/PMC3416023/). SciPy's general two-sided convention may differ from absolute-tail conventions; the formulas here define this implementation.
