# Scenario B ground truth

| File | Planted as | Expected | Observed |
|---|---|---|---|
| salary.xlsx | deleted + keyword | deleted, recovered, keyword | PASS |
| passwords.txt | deleted + keyword | deleted, recovered, keyword | PASS |
| report.pdf | ZIP disguised as PDF | magic mismatch | PASS |
| invoice.jpg | EXE disguised as JPG | magic mismatch | PASS |
| secret.txt | hidden attribute | hidden flag | PASS |
| client_list.docx | keyword in name | keyword flag | PASS |
| notes.txt, holiday.jpg | clean | no flags | PASS |

Detection: 6/6 true positives, 0 false positives. Recovery: 2/2.
