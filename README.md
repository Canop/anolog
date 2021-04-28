
[![Latest Version][s1]][l1] [![MIT][s2]][l2] [![Chat on Miaou][s3]][l3]

[s1]: https://img.shields.io/crates/v/anolog.svg
[l1]: https://crates.io/crates/anolog

[s2]: https://img.shields.io/badge/license-MIT-blue.svg
[l2]: LICENSE

[s3]: https://miaou.dystroy.org/static/shields/room.svg
[l3]: https://miaou.dystroy.org/3768?rust


Anolog anonymizes access log files.

It replaces IPv4, Ipv6 and query parameter values with random ones.

To keep the likelihood of the resulting log files, and keep them as useful as possible to test log based tools, there are constraints for the replacements:

* All strings are consistently replaced: A string is always, in the same file, replaced by the same value, which allows for example to keep the validity of visit analysis
* A replacement is always the size of the replaced
* localhost IP aren't replaced

Usage:

```bash
anolog path/to/server.access.log > anonym.log
```


:warning: Anolog comes without any kind of garantee. If a file is converted with anolog, it may still contain private data and may still help an attacker.
