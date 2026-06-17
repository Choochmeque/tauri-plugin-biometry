## Default Permission

This permission set configures the biometry commands that are safe to grant
without any per-call scoping.

#### Granted Permissions

Only the non-storage commands (`status` and `authenticate`) are granted by
default. Storage commands (`has_data`, `get_data`, `set_data`, `remove_data`)
require explicit per-capability grants together with an `allow` scope listing
the `(domain, name)` pairs the calling webview is permitted to touch.

Example capability JSON for storage:

```json
{
  "identifier": "default",
  "windows": ["main"],
  "permissions": [
    "biometry:default",
    { "identifier": "biometry:allow-get-data",
      "allow": [{ "domain": "com.myapp.creds" }] },
    { "identifier": "biometry:allow-set-data",
      "allow": [{ "domain": "com.myapp.creds" }] }
  ]
}
```

#### This default permission set includes the following:

- `allow-authenticate`
- `allow-status`

## Permission Table

<table>
<tr>
<th>Identifier</th>
<th>Description</th>
</tr>


<tr>
<td>

`biometry:allow-authenticate`

</td>
<td>

Enables the authenticate command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:deny-authenticate`

</td>
<td>

Denies the authenticate command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:allow-get-data`

</td>
<td>

Enables the get_data command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:deny-get-data`

</td>
<td>

Denies the get_data command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:allow-has-data`

</td>
<td>

Enables the has_data command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:deny-has-data`

</td>
<td>

Denies the has_data command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:allow-remove-data`

</td>
<td>

Enables the remove_data command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:deny-remove-data`

</td>
<td>

Denies the remove_data command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:allow-set-data`

</td>
<td>

Enables the set_data command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:deny-set-data`

</td>
<td>

Denies the set_data command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:allow-status`

</td>
<td>

Enables the status command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`biometry:deny-status`

</td>
<td>

Denies the status command without any pre-configured scope.

</td>
</tr>
</table>
