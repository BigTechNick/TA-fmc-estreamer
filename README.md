# eStreamer Add-on for Cisco Secure Firewall (FMC/Firepower)

Splunk add-on `TA-fmc-estreamer`, version 2.2.2.

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

## Packages

`packages/` holds each version's package exactly as uploaded to Splunkbase, with `MD5SUMS`.
Each version is also its own commit (`git log`).

## License

Apache-2.0. Independent project, not affiliated with or endorsed by Cisco.
