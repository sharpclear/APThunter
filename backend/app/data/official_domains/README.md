# Official Domain Whitelist

Place the system-wide impersonation protection whitelist here:

```text
backend/app/data/official_domains/full_whitelist.csv
```

The backend container reads the same file at:

```text
/app/app/data/official_domains/full_whitelist.csv
```

Supported formats are `csv`, `txt`, and `xlsx`. Recommended CSV columns:

```csv
company,domain
Microsoft,microsoft.com
Google,google.com
```

If an impersonation subscription uploads an official domain file, that uploaded file
overrides this system-wide whitelist for that subscription.
