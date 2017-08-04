# Scopes

In addition to rules, Santa can whitelist or blacklist based on a scope. There are currently only a few scopes implemented. Scopes fall into one of two categories, a whitelist scope or a blacklist scope. Scopes are evaluated after rules. The blacklist scopes are evaluated before the whitelist scopes.

Scopes are simply less specific or broader way of whitelisting or blacklisting `exec()`.

For configuration of scopes see the [configuration.md](../deployment/configuration.md).

##### Blacklist Scopes

| Scope                | Configurable |
| -------------------- | ------------ |
| Blacklist Path Regex | Yes          |
| Missing __PAGEZERO   | Yes          |

##### Whitelist Scopes

| Scope                | Configurable |
| -------------------- | ------------ |
| Whitelist Path Regex | Yes          |
| Not a Mach-O         | No           |

As seen above, Santa will whitelist any non Mach-O as a whitelist scope. Though, a blacklist regex or binary SHA-256 rule can be used to block a non Mach-O `exec()` since they are evaluated before the whitelist scopes.