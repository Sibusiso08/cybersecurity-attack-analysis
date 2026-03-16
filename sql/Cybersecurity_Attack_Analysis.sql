-- =========================================================
-- CYBERSECURITY ATTACK DATASET - MySQL Analysis Project
-- Author  : Sibusiso D. Mbuyane
-- Dataset : 13,867 Documented Attack Scenarios
-- Tool    : MySQL (compatible with SQLite)
-- =========================================================


-- -------------------------
-- STEP 1: DATABASE SETUP
-- -------------------------

CREATE DATABASE IF NOT EXISTS cybersecurity_db;
USE cybersecurity_db;


-- -------------------------
-- STEP 2: CREATE TABLE
-- -------------------------

CREATE TABLE IF NOT EXISTS attacks (
  id                 INT PRIMARY KEY,
  title              TEXT,
  category           VARCHAR(255),
  attack_type        VARCHAR(255),
  scenario_description TEXT,
  tools_used         TEXT,
  attack_steps       TEXT,
  target_type        VARCHAR(255),
  vulnerability      TEXT,
  mitre_technique    VARCHAR(255),
  impact             TEXT,
  detection_method   TEXT,
  solution           TEXT,
  tags               TEXT,
  source             TEXT,
  notes              VARCHAR(255)
);


-- -------------------------
-- STEP 3: EXPLORE THE DATA
-- -------------------------

-- Preview all records
SELECT *
FROM attacks;

-- Total row count
SELECT COUNT(*) AS total_records
FROM attacks;

-- Preview distinct categories
SELECT DISTINCT category
FROM attacks
ORDER BY category;

-- Check for any remaining NULLs
SELECT
    SUM(CASE WHEN title              IS NULL OR title              = '' THEN 1 ELSE 0 END) AS missing_title,
    SUM(CASE WHEN category           IS NULL OR category           = '' THEN 1 ELSE 0 END) AS missing_category,
    SUM(CASE WHEN attack_type        IS NULL OR attack_type        = '' THEN 1 ELSE 0 END) AS missing_attack_type,
    SUM(CASE WHEN target_type        IS NULL OR target_type        = '' THEN 1 ELSE 0 END) AS missing_target_type,
    SUM(CASE WHEN mitre_technique    IS NULL OR mitre_technique    = '' THEN 1 ELSE 0 END) AS missing_mitre,
    SUM(CASE WHEN source             IS NULL OR source             = '' THEN 1 ELSE 0 END) AS missing_source
FROM attacks;


-- -------------------------
-- STEP 4: STAGING TABLE
-- -------------------------

-- Create a working staging copy so raw data stays untouched
CREATE TABLE attacks_staging
LIKE attacks;

INSERT INTO attacks_staging
SELECT *
FROM attacks;

SELECT *
FROM attacks_staging;


-- -------------------------
-- STEP 5: DATA CLEANING
-- -------------------------

-- Fix category casing inconsistency
UPDATE attacks_staging
SET category = 'Network Security'
WHERE category = 'Network security';

-- Trim whitespace from key columns
UPDATE attacks_staging
SET
    category    = TRIM(category),
    attack_type = TRIM(attack_type),
    target_type = TRIM(target_type),
    source      = TRIM(source);

-- Add attack_family column for grouping
ALTER TABLE attacks_staging
ADD COLUMN attack_family VARCHAR(100);

-- Populate attack_family using CASE grouping
-- (reduces 8,833 unique attack types into 19 meaningful families)
UPDATE attacks_staging
SET attack_family =
    CASE
        WHEN LOWER(attack_type) LIKE '%sql injection%'
          OR LOWER(attack_type) LIKE '%sqli%'              THEN 'SQL Injection'
        WHEN LOWER(attack_type) LIKE '%xss%'
          OR LOWER(attack_type) LIKE '%cross-site script%' THEN 'Cross-Site Scripting (XSS)'
        WHEN LOWER(attack_type) LIKE '%phishing%'
          OR LOWER(attack_type) LIKE '%social engineer%'   THEN 'Phishing / Social Engineering'
        WHEN LOWER(attack_type) LIKE '%brute force%'
          OR LOWER(attack_type) LIKE '%password spray%'    THEN 'Brute Force / Credential Attack'
        WHEN LOWER(attack_type) LIKE '%ransomware%'        THEN 'Ransomware'
        WHEN LOWER(attack_type) LIKE '%privilege escalation%' THEN 'Privilege Escalation'
        WHEN LOWER(attack_type) LIKE '%denial of service%'
          OR LOWER(attack_type) LIKE '%ddos%'
          OR LOWER(attack_type) LIKE '%dos%'               THEN 'Denial of Service (DoS/DDoS)'
        WHEN LOWER(attack_type) LIKE '%malware%'
          OR LOWER(attack_type) LIKE '%trojan%'
          OR LOWER(attack_type) LIKE '%backdoor%'          THEN 'Malware / Trojan / Backdoor'
        WHEN LOWER(attack_type) LIKE '%ssrf%'              THEN 'SSRF'
        WHEN LOWER(attack_type) LIKE '%injection%'         THEN 'Other Injection Attacks'
        WHEN LOWER(attack_type) LIKE '%supply chain%'      THEN 'Supply Chain Attack'
        WHEN LOWER(attack_type) LIKE '%credential%'        THEN 'Credential Theft / Stuffing'
        WHEN LOWER(attack_type) LIKE '%lateral movement%'  THEN 'Lateral Movement'
        WHEN LOWER(attack_type) LIKE '%man-in-the-middle%'
          OR LOWER(attack_type) LIKE '%mitm%'              THEN 'Man-in-the-Middle (MITM)'
        WHEN LOWER(attack_type) LIKE '%fuzzing%'           THEN 'Fuzzing'
        WHEN LOWER(attack_type) LIKE '%prompt injection%'  THEN 'Prompt Injection (AI/LLM)'
        WHEN LOWER(attack_type) LIKE '%data poison%'
          OR LOWER(attack_type) LIKE '%poisoning%'         THEN 'Data / Model Poisoning'
        WHEN LOWER(attack_type) LIKE '%recon%'
          OR LOWER(attack_type) LIKE '%reconnaissance%'    THEN 'Reconnaissance'
        WHEN LOWER(attack_type) LIKE '%exfiltration%'
          OR LOWER(attack_type) LIKE '%exfil%'             THEN 'Data Exfiltration'
        WHEN LOWER(attack_type) LIKE '%buffer overflow%'
          OR LOWER(attack_type) LIKE '%heap overflow%'     THEN 'Buffer / Heap Overflow'
        ELSE 'Other'
    END;

-- Verify staging table is clean
SELECT *
FROM attacks_staging
LIMIT 20;


-- -------------------------
-- STEP 6: ANALYSIS QUERIES
-- -------------------------

-- Q1: How many attacks are recorded per category?
SELECT
    category,
    COUNT(*)                                                       AS total_attacks,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM attacks_staging), 2) AS pct_of_total
FROM attacks_staging
GROUP BY category
ORDER BY total_attacks DESC;


-- Q2: Top 15 most common specific attack types
SELECT
    attack_type,
    COUNT(*) AS frequency
FROM attacks_staging
GROUP BY attack_type
ORDER BY frequency DESC
LIMIT 15;


-- Q3: Top 10 most targeted system / target types
SELECT
    target_type,
    COUNT(*) AS times_targeted
FROM attacks_staging
WHERE target_type NOT LIKE '%DATA BLEED%'
  AND TRIM(target_type) != ''
  AND target_type IS NOT NULL
GROUP BY target_type
ORDER BY times_targeted DESC
LIMIT 10;


-- Q4: Top 10 most referenced MITRE ATT&CK techniques
SELECT
    mitre_technique,
    COUNT(*) AS frequency
FROM attacks_staging
WHERE TRIM(mitre_technique) != ''
  AND mitre_technique IS NOT NULL
GROUP BY mitre_technique
ORDER BY frequency DESC
LIMIT 10;


-- Q5: Most common attack impacts (Top 15)
SELECT
    TRIM(impact) AS impact_type,
    COUNT(*)     AS frequency
FROM attacks_staging
WHERE TRIM(impact) != ''
  AND impact IS NOT NULL
GROUP BY TRIM(impact)
ORDER BY frequency DESC
LIMIT 15;


-- Q6: Which categories have attacks with no solution documented?
SELECT
    category,
    COUNT(*) AS attacks_without_solution
FROM attacks_staging
WHERE TRIM(solution) = ''
   OR solution IS NULL
GROUP BY category
ORDER BY attacks_without_solution DESC;


-- Q7: Detection coverage by category
-- (how many attacks in each category have a detection method listed)
SELECT
    category,
    SUM(CASE WHEN TRIM(detection_method) != '' THEN 1 ELSE 0 END) AS has_detection,
    SUM(CASE WHEN TRIM(detection_method)  = '' THEN 1 ELSE 0 END) AS no_detection,
    COUNT(*)                                                        AS total,
    ROUND(
        SUM(CASE WHEN TRIM(detection_method) != '' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1
    )                                                               AS detection_coverage_pct
FROM attacks_staging
GROUP BY category
ORDER BY total DESC;


-- Q8: Most dangerous categories by high-impact attack count
-- high impact = data theft, privilege escalation, ransomware,
--               account takeover, or remote code execution in impact field
SELECT
    category,
    COUNT(*) AS high_impact_attacks
FROM attacks_staging
WHERE LOWER(impact) LIKE '%data theft%'
   OR LOWER(impact) LIKE '%privilege escalation%'
   OR LOWER(impact) LIKE '%ransomware%'
   OR LOWER(impact) LIKE '%account takeover%'
   OR LOWER(impact) LIKE '%remote code execution%'
GROUP BY category
ORDER BY high_impact_attacks DESC
LIMIT 15;


-- Q9: Source distribution grouped by known security frameworks
SELECT
    CASE
        WHEN source = 'Unknown'         THEN 'No Source'
        WHEN source LIKE '%OWASP%'      THEN 'OWASP'
        WHEN source LIKE '%MITRE%'      THEN 'MITRE ATT&CK'
        WHEN source LIKE '%CVE%'
          OR source LIKE '%NVD%'        THEN 'CVE/NVD'
        WHEN source LIKE '%NIST%'       THEN 'NIST'
        ELSE 'Other Sources'
    END AS source_group,
    COUNT(*) AS total
FROM attacks_staging
GROUP BY source_group
ORDER BY total DESC;


-- Q10: Attack type families - grouped count
-- (excludes "Other" for cleaner reporting)
SELECT
    attack_family,
    COUNT(*) AS total_attacks
FROM attacks_staging
WHERE attack_family != 'Other'
GROUP BY attack_family
ORDER BY total_attacks DESC;


-- -------------------------
-- STEP 7: BONUS QUERIES
-- -------------------------

-- How many unique attack types exist per category?
SELECT
    category,
    COUNT(DISTINCT attack_type) AS unique_attack_types
FROM attacks_staging
GROUP BY category
ORDER BY unique_attack_types DESC
LIMIT 15;


-- Which attack families have the highest average impact severity?
-- (proxy: count of records with "critical" or "full" in impact field)
SELECT
    attack_family,
    COUNT(*) AS critical_impact_count
FROM attacks_staging
WHERE LOWER(impact) LIKE '%critical%'
   OR LOWER(impact) LIKE '%full system%'
   OR LOWER(impact) LIKE '%complete%'
GROUP BY attack_family
ORDER BY critical_impact_count DESC
LIMIT 10;


-- Top 10 most common tools used across all attacks
SELECT
    TRIM(tools_used) AS tool,
    COUNT(*) AS times_mentioned
FROM attacks_staging
WHERE TRIM(tools_used) != ''
  AND tools_used IS NOT NULL
GROUP BY TRIM(tools_used)
ORDER BY times_mentioned DESC
LIMIT 10;


-- Cross-tab: category vs attack family (top combinations)
SELECT
    category,
    attack_family,
    COUNT(*) AS total
FROM attacks_staging
WHERE attack_family != 'Other'
GROUP BY category, attack_family
ORDER BY total DESC
LIMIT 20;
