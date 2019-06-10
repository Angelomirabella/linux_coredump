# Linux Coredump
Linux Coredump is a volatility plugin that attempts to create a core dump file starting from the memory of a Linux process.

## Usage
* Clone or download the linux\_coredump plugin.
* Issue the command:

    ```bash
    volatility --plugins=<path of extracted linux_coredump dir> --profile=<memory profile> -f <memory dump> linux_coredump --pid <process pid> --dump-dir <output dir> --output-file <output file>
    ```
    or
   ```bash
    vol.py --plugins=<path of extracted linux_coredump dir> --profile=<memory profile> -f <memory dump> linux_coredump --pid <process pid> --dump-dir <output dir> --output-file <output file>
    ```
Depending on how you installed volatility (from apt or github).

The plugin will output the corefile in the specified directory and with the specified file name.


### NOTES
* The --plugins option must be the first option.
* The plugin may require some time for processes that use a lot of memory (up to 15-20 minutes).
* The volatility version installed using apt differs from the one present in ([github]: https://github.com/volatilityfoundation/volatility). This latter version probably has a bug and does not show the name of the process memory mappings.
