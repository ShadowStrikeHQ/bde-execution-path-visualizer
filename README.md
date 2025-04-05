# bde-Execution-Path-Visualizer
A command-line tool that generates a call graph visualization of a potentially obfuscated script's execution, focusing on branching logic and function calls to identify suspicious or unusual control flow patterns. Output can be a graphviz dot file. - Focused on Automatically identifies and deobfuscates potentially malicious code snippets (e.g., JavaScript, PowerShell) through behavioral analysis. It uses techniques like string decoding, variable renaming, and control flow simplification to expose the underlying functionality, enabling easier malware analysis and identification of malicious intent without full emulation. Differs from 'analyze' by focusing on code transformation rather than static analysis.

## Install
`git clone https://github.com/ShadowStrikeHQ/bde-execution-path-visualizer`

## Usage
`./bde-execution-path-visualizer [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: No description provided
- `-v`: Enable verbose logging
- `--beautify`: Beautify the input script before analysis.
- `--decode_strings`: Attempt to decode base64 and hex encoded strings.
- `--rename_variables`: Attempt to rename obfuscated variables.

## License
Copyright (c) ShadowStrikeHQ
