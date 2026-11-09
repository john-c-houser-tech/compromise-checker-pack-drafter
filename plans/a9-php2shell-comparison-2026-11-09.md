# A.9: PHP2Shell regenerated blind, compared with the signed pack (2026-11-09)

The drafter rebuilt PHP2Shell (CVE-2026-109618, CVE-2026-109619) from the store
alone, without the signed `php2shell-2026-10`. It was assembled in a scratch clone
of the packs repository, for comparison only; it isn't for release. Its store
record (pack_assembly 2) names the reviewer "claude (A.9 comparison, not for
release)", because John didn't review its prose.

**How blind it was.** The AI draft was blind: it saw only the eight sources in
its header. The assembly choices were less so:
- Claude had read `php2shell_proof.py` earlier, which shows the signed pack's
  upload-progress mitigation and crash and memory-error detections.
- The assembly template's weight hint reads "(PHP2Shell: 5)".
- John knew the signed pack.

## Time and cost

| | Signed (by hand) | Regenerated |
|---|---|---|
| Ready | 2026-10-30, 9 days after disclosure, with its own proof (hand-writing time not recorded) | 56 minutes from John's approval to a valid pack: draft 2 min, then fill, propose and five decisions by John |
| AI cost | none | $0.12 (one draft, Opus 5.5) |

## Where they agree

- Same CVEs, the same six releases, other_builds `cant_judge`, weight 5.
- Every fixed version from Ubuntu, Red Hat, Sury and Remi is the same in both.
- Both have the RHEL 9 php:8.4 stream with no fix, and the Ubuntu 22.04 libapache2-mod-php7.4/8.0 entry.
- Both use worker-child, new-script-hit and error detections, and give restart and compromise remediation.

## What the regenerated pack missed

1. **The mitigation.** The signed pack checks `session.upload_progress.enabled`
   (off blocks one route to CVE-2026-109619). The draft has none. The AI said why:
   Red Hat's bulletin (RHSB-2026-013) with the mitigation wasn't among the
   sources. Cause: the drafter fetches only vendor CVE records, NVD and CISA, not
   the bulletins and advisories they link to.
2. **The window's true start.** The signed pack starts on 10-20, when the details
   leaked (Sansec's timeline), with first attacks on 10-21 07:43 (Cloudflare).
   The regenerated one starts on 10-21 with no first sighting. Same cause: no
   researcher or CDN sources.
3. **Detections written for this threat.** The signed pack's `php-crash` (worker
   signals 11, 6 and 7, at least 6 in 10 minutes) and `memory-limit-burst` (at
   least 30 memory-limit errors in 10 minutes) come from the exploit's research.
   The draft has generic built-in checks only, and says the sources don't describe
   the requests or log lines.
4. **Weights for the detections.** The signed pack gives worker-child 100 and
   new-script-hit 50. The draft gives 20 and 5: far weaker evidence for the same
   sign. The AI flagged that its ratios needed review.
5. **LiteSpeed and Remi's Apache module.** The binary filter I proposed (John
   approved it) left out `*-litespeed` / `lsphp*` and Remi's `phpXX-php` (its
   mod_php). A host whose only PHP runtime is one of those reads not affected.
6. **AlmaLinux's own early builds** (`*.alma.1`, `module_el9…`, from Alma's
   blog). Only one is in the regenerated pack. The rest read can't judge rather
   than fixed, which is safe but less precise.
7. **Remediation substance.** The draft doesn't say to rotate secrets the PHP
   process could read, and doesn't name what the pack can't judge (cPanel and
   Plesk PHP, bundled PHP, Ubuntu 20.04 and older, RHEL 8).
8. **The name.** The draft never says "PHP2Shell", which no source used.

## What the regenerated pack got wrong, or worse

1. **`apache2` and `httpd` in stale_code** (my recommendation). They would flag
   every Apache started before the fix, including those that pass PHP to FPM and
   never load mod_php. The signed pack leaves Apache out on purpose and says so
   in its remediation.
2. **php-cli, php-dbg and the embed SAPIs counted.** A host with PHP only on the
   command line reads vulnerable, though the flaws are reached through web
   requests. The signed pack counts the web-facing SAPIs on Ubuntu (it does keep
   php-cli on RHEL).
3. **PHP 8.6 release candidates read can't judge** (unconfirmed). The signed
   pack calls them vulnerable (`fixed: null`, versions `8.6.0~*`). Both are safe;
   the signed pack is firmer.
4. **Remediation text.** It points to a mitigation "these sources do not
   include", which is honest but no help to an operator.

## Drafter defects found

- **`propose` makes nonsense Remi proposals.** Without a binary filter it
  grouped Remi's pecl extension packages by their own versions, as if they were
  PHP branches: 366 of 418 proposals. Fix it in `propose` (group by the PHP
  branch the package belongs to, or leave out packages that aren't PHP's own).
- **The template's weight hint names PHP2Shell's weight.** That anchors every
  new pack. Give the scale, not another pack's value.
- **No researcher sources.** Mitigations, the leak date, first sightings and
  exploit-specific detections all came from pages the drafter never fetches:
  vendor bulletins, project advisories (GHSA), research write-ups. The biggest
  gap. Options: fetch the advisories and bulletins a record links to, or let a
  person attach sources before the draft.

## What follows for the plan

- A generated pack is a sound package base: the fixed versions matched exactly,
  including Sury and Remi. Its prose, detections and weights are a first draft
  that needs the person who knows the threat.
- Before more packs: fix `propose`, drop the template's PHP2Shell hint, and keep
  a checklist for the binary filter (every SAPI: fpm, cgi, mod_php under each
  vendor's name, litespeed) and for stale_code (only programs that certainly run
  the fixed code).
- Adding linked advisories and bulletins as sources is the change that would
  have closed most of the gaps above.
