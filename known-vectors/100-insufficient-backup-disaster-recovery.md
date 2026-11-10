---
id: 100
title: "Insufficient Backup / Disaster Recovery"
severity: 7
category: devops
---

### 100 — Insufficient Backup / Disaster Recovery
**Severity: 7** | **Real: GitLab database deletion incident (2017), Code Spaces shutdown (AWS console compromised)**

No backups, or untested backups → database corruption, accidental deletion, or ransomware wipes everything.

#### Verification Procedure

**Step 1: Check for database backup configuration**
```
grep -rn --include="*.yaml" --include="*.yml" --include="*.ts" -iE "backup|mongodump|snapshot|retention" . | grep -v node_modules | head -10
```
- ✅ PASS: Automated database backups configured (cloud provider or cron)
- ❌ FAIL: No backup configuration

**Step 2: Check MongoDB Atlas backup (if using Atlas)**
```
# Atlas: Database → Backup → verify backup policy
# - Continuous backup or scheduled snapshots?
# - Retention period?
```
- ✅ PASS: Continuous backup or daily snapshots with ≥7 day retention
- ⚠️ PARTIAL: Snapshots exist but short retention
- ❌ FAIL: No backups configured

**Step 3: Check for code/infrastructure backup**
```
# Is the git repo the single source of truth?
# Are there other critical configs not in version control?
"<auditor-skill root>/scripts/git-ro.sh" remote -v   # read-only git (Rule 11c)
```
- ✅ PASS: All code in version control, infrastructure as code, multiple remotes
- ❌ FAIL: Single point of failure (one GitHub repo, no mirrors)

**Step 4: Check for recovery procedure documentation**
```
grep -rliE --include='*.md' 'disaster|recovery|restore|backup.*procedure' . | head -5
```
- ✅ PASS: Documented disaster recovery procedure
- ⚠️ PARTIAL: Backups exist but no documented recovery procedure
- ❌ FAIL: No backups or recovery documentation

**Step 5: Check for backup testing**
```
# Has backup restoration ever been tested?
# When was the last test recovery?
```
- ✅ PASS: Backup restoration tested within last 90 days
- ⚠️ PARTIAL: Backups configured but never tested
- ❌ FAIL: No backup testing, no confidence in restoration

**Overall verdict:**
- ✅: Automated backups, documented recovery, tested restoration, multiple redundancy
- ⚠️: Backups exist but untested or undocumented
- ❌: No backups — total data loss risk
