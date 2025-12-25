# Ecosystem Mapping Reference

Mapping between language names, package ecosystems, and PURL schemes.

## Common Ecosystems

| Language | Ecosystem | PURL Scheme | Package Manager |
|----------|-----------|-------------|-----------------|
| Python | PyPI | `pkg:pypi/` | pip |
| JavaScript | npm | `pkg:npm/` | npm/yarn/pnpm |
| Java | Maven | `pkg:maven/` | Maven/Gradle |
| Go | Go | `pkg:golang/` | go mod |
| Ruby | RubyGems | `pkg:gem/` | gem/bundler |
| PHP | Packagist | `pkg:composer/` | composer |
| Rust | crates.io | `pkg:cargo/` | cargo |
| .NET | NuGet | `pkg:nuget/` | nuget/dotnet |

## Full Ecosystem List (OSV.dev Supported)

### Programming Languages

| Ecosystem | Description |
|-----------|-------------|
| `PyPI` | Python Package Index |
| `npm` | Node.js packages |
| `Maven` | Java/Kotlin packages |
| `Go` | Go modules |
| `RubyGems` | Ruby gems |
| `Packagist` | PHP packages |
| `crates.io` | Rust crates |
| `NuGet` | .NET packages |
| `Hex` | Erlang/Elixir packages |
| `Pub` | Dart/Flutter packages |
| `SwiftURL` | Swift packages |
| `CocoaPods` | iOS/macOS packages |

### Linux Distributions

| Ecosystem | Description |
|-----------|-------------|
| `Debian` | Debian packages |
| `Alpine` | Alpine Linux packages |
| `Ubuntu` | Ubuntu packages |
| `Rocky Linux` | Rocky Linux packages |
| `AlmaLinux` | AlmaLinux packages |

### Other

| Ecosystem | Description |
|-----------|-------------|
| `GIT` | Git repositories |
| `OSS-Fuzz` | OSS-Fuzz findings |
| `Android` | Android packages |
| `Linux` | Linux kernel |

## PURL Format

Package URL (PURL) format: `pkg:<type>/<namespace>/<name>@<version>`

### Examples

```
# Python
pkg:pypi/jinja2@3.0.0
pkg:pypi/django@4.2.0

# JavaScript
pkg:npm/lodash@4.17.21
pkg:npm/@angular/core@15.0.0      # Scoped package

# Java
pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1
pkg:maven/com.google.guava/guava@31.0-jre

# Go
pkg:golang/github.com/gin-gonic/gin@v1.9.1
pkg:golang/golang.org/x/net@v0.17.0

# Ruby
pkg:gem/rails@7.0.0
pkg:gem/nokogiri@1.15.0

# PHP
pkg:composer/symfony/http-foundation@6.3.0
pkg:composer/laravel/framework@10.0.0

# Rust
pkg:cargo/serde@1.0.188
pkg:cargo/tokio@1.32.0

# .NET
pkg:nuget/Newtonsoft.Json@13.0.3
pkg:nuget/Microsoft.AspNetCore.Mvc@2.2.0
```

## Querying by Ecosystem

### OSV.dev Query Examples

```bash
# Python ecosystem
curl -s "https://api.osv.dev/v1/query" -d '{
  "package": {"ecosystem": "PyPI"}
}'

# Specific Python package
curl -s "https://api.osv.dev/v1/query" -d '{
  "package": {"name": "jinja2", "ecosystem": "PyPI"}
}'

# Using PURL (recommended when version known)
curl -s "https://api.osv.dev/v1/query" -d '{
  "package": {"purl": "pkg:pypi/jinja2@3.0.0"}
}'
```

## Mapping User Input to Ecosystem

| User Input | Ecosystem | Notes |
|------------|-----------|-------|
| `python`, `pypi`, `pip` | PyPI | |
| `javascript`, `js`, `npm`, `node` | npm | |
| `java`, `maven`, `gradle` | Maven | |
| `go`, `golang` | Go | |
| `ruby`, `gem`, `rubygems` | RubyGems | |
| `php`, `composer`, `packagist` | Packagist | |
| `rust`, `cargo`, `crates` | crates.io | |
| `dotnet`, `csharp`, `nuget` | NuGet | |

## Package Name Formats

### Scoped Packages

**npm:** `@scope/package` → PURL: `pkg:npm/@scope/package`
```bash
# Query scoped npm package
curl -s "https://api.osv.dev/v1/query" -d '{
  "package": {"name": "@angular/core", "ecosystem": "npm"}
}'
```

### Namespaced Packages

**Maven:** `groupId:artifactId` → PURL: `pkg:maven/groupId/artifactId`
```bash
# Query Maven package
curl -s "https://api.osv.dev/v1/query" -d '{
  "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"}
}'
```

### Go Modules

**Go:** Full module path → PURL: `pkg:golang/path`
```bash
# Query Go module
curl -s "https://api.osv.dev/v1/query" -d '{
  "package": {"name": "github.com/gin-gonic/gin", "ecosystem": "Go"}
}'
```

## Language to Semgrep Support

| Ecosystem | Semgrep Support | Taint Mode | Notes |
|-----------|-----------------|------------|-------|
| PyPI | Excellent | Yes | Full type inference |
| npm | Excellent | Yes | JS and TS |
| Maven | Excellent | Yes | Java and Kotlin |
| Go | Excellent | Yes | |
| RubyGems | Good | Yes | |
| Packagist | Good | Yes | PHP |
| crates.io | Moderate | Limited | Rust support improving |
| NuGet | Good | Yes | C# |

## Converting Package Input

When user provides package name, determine ecosystem:

```
jinja2          → PyPI (default for unqualified Python-looking names)
jinja2@pypi     → PyPI
lodash@npm      → npm
log4j@maven     → Maven
gin@go          → Go
rails@gem       → RubyGems
symfony@php     → Packagist
```

Or ask for clarification if ambiguous.
