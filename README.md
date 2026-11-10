# Nikhil Chawla Add-on for Cisco Secure Firewall eStreamer (FMC)

Splunk add-on `TA-fmc-estreamer`, version 2.2.1.

Collects events from a Secure Firewall Management Center (FMC) over eStreamer: connection, policy violation, VPN, FireAMP, file, intrusion and packet events, for Splunk as sourcetype cisco:sfw:estreamer and/or as CEF files. CIM mapping needs the Cisco Security Cloud app on the search heads. Inputs, certificates and status are managed in Splunk Web. Not affiliated with Cisco.

Splunkbase: https://splunkbase.splunk.com/app/10081

## Layout

- `TA-fmc-estreamer/`: the app exactly as shipped to Splunkbase (unpacked from the release package)
- `tools/package.py`: builds the Splunkbase package and runs offline AppInspect-style checks

## Build

```
python3 tools/package.py TA-fmc-estreamer dist --vendor cisco
```

Good: `RESULT: OK`. Then AppInspect:

```
splunk-appinspect inspect dist/TA-fmc-estreamer-<version>.tgz --mode precert --included-tags cloud
```

## Releases

Each version is tagged `v<version>`. Its GitHub release has the exact package uploaded to
Splunkbase attached, with its md5.

## License

Apache-2.0. Independent project, not affiliated with or endorsed by Cisco.
