# External References

These references anchor product direction. They are not claims that Sentinel is
equivalent to these projects.

## EICAR

Link: https://www.eicar.org/download-anti-malware-testfile/

Use in Sentinel: safe demo fixture for anti-malware response testing without
using real malware.

Product rule: generate the EICAR file at demo time and keep the literal file out
of Git.

## YARA

Link: https://yara.readthedocs.io/en/latest/

Use in Sentinel: future rule-compatibility direction. YARA is a natural
reference because it uses textual or binary patterns plus rule logic to identify
and classify malware-like artifacts.

Product rule: YARA support is a future bridge, not an MVP dependency.

## ClamAV

Link: https://docs.clamav.net/

Use in Sentinel: mature open-source scanner reference point for command-line
scanning, daemon mode, signature updates, and scanner-engine separation.

Product rule: compare against ClamAV for learning and baseline behavior, not as
a claim that Sentinel is a replacement.

## MITRE ATT&CK

Link: https://attack.mitre.org/

Use in Sentinel: optional future mapping layer when a rule has a reasonable
connection to adversary tactics or techniques.

Product rule: ATT&CK mappings should be hints, not conclusions or intrusion
claims.
