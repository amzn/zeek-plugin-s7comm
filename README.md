## Zeek Plugin S7comm

When running as part of your Zeek installation this plugin will produce two log files containing metadata extracted from any ISO COTP and Siemens S7 traffic observed on TCP port 102. S7 uses COTP as transport.

## Installation and Usage

`zeek-plugin-s7comm` is distributed as a Zeek package and is compatible with the [`zkg`](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html) command line tool.

## Sharing and Contributing

This code is made available under the [BSD-3-Clause license](https://github.com/amzn/zeek-plugin-s7comm/blob/master/LICENSE). [Guidelines for contributing](https://github.com/amzn/zeek-plugin-s7comm/blob/master/CONTRIBUTING.md) are available as well as a [pull request template](https://github.com/amzn/zeek-plugin-s7comm/blob/master/.github/PULL_REQUEST_TEMPLATE.md). A [Dockerfile](https://github.com/amzn/zeek-plugin-s7comm/blob/master/Dockerfile) has been included in the repository to assist with setting up an environment for testing any changes to the plugin.

## Acknowledgements

* [Earlier work](https://github.com/CrySyS/bro-step7-plugin) on S7 parsing by the [Laboratory of Cryptography and System Security](https://www.crysys.hu/)
