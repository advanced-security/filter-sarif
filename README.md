# filter-sarif

Takes a SARIF file and a list of inclusion and exclusion patterns as input and removes alerts from the SARIF file according to those patterns.

## Example

The following example removes all alerts from all Java test files:

```yaml
name: "Filter SARIF"
on:
  push:
    branches: [master]

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest

    strategy:
      fail-fast: false
      matrix:
        language: [ 'java' ]

    steps:
    - name: Checkout repository
      uses: actions/checkout@v2

    - name: Initialize CodeQL
      uses: github/codeql-action/init@v2
      with:
        languages: ${{ matrix.language }}

    - name: Autobuild
      uses: github/codeql-action/autobuild@v2

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
      with:
        upload: False
        output: sarif-results

    - name: filter-sarif
      uses: advanced-security/filter-sarif@main
      with:
        patterns: |
          +**/*.java
          -**/*Test*.java
        input: sarif-results/java.sarif
        output: sarif-results/java.sarif

    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: sarif-results/java.sarif

    - name: Upload loc as a Build Artifact
      uses: actions/upload-artifact@v2.2.0
      with:
        name: sarif-results
        path: sarif-results
        retention-days: 1
```

Note how we provided `upload: False` and `output: sarif-results` to the `analyze` action. That way we can filter the SARIF with the `filter-sarif` action before uploading it via `upload-sarif`. Finally, we also attach the resulting SARIF file to the build, which is convenient for later inspection.

## Patterns

Each pattern line is of the form:

```yaml
[+/-]<file pattern>[:<rule pattern>][:<message pattern>]
```

for example:

```yaml
-**/*Test*.java:**               # exclusion pattern: remove all alerts from all Java test files
-**/*Test*.java                  # ditto, short form of the line above
+**/*.java:java/sql-injection    # inclusion pattern: This line has precedence over the first two
                                 # and thus "whitelists" alerts of type "java/sql-injection"
**/*.java:java/sql-injection     # ditto, the "+" in inclusion patterns is optional
**                               # allow all alerts in all files (reverses all previous lines)
```

Subsequent lines override earlier ones. By default all alerts are included.

The file pattern:

* The path separator character in patterns is always `/`, independent of the platform the code is running on and independent of the paths in the SARIF file.
* `*` matches any character, except a path separator
* `**` matches any character and is only allowed between path separators, e.g. `/**/file.txt`, `**/file.txt` or `**`. NOT allowed: `**.txt`, `/etc**`

The rule pattern:

* The rule pattern is optional. If omitted, it will apply to alerts of all types.

For the file and rule patterns:

* If you need to use the literals `+`, `-`, `\` or `:` in your pattern, you can escape them with `\`, e.g. `\-this/is/an/inclusion/file/pattern\:with-a-semicolon:and/a/rule/pattern/with/a/\\/backslash`. For `+` and `-`, this is only necessary if they appear at the beginning of the pattern line.

The message pattern:

* The message pattern is optional. If omitted, it will apply to all messages.
* The syntax is python regular expressions. Take care with backtracking and repetition to avoid performance problems.
